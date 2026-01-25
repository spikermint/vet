use std::path::{Path, PathBuf};

use anyhow::Context as _;
use chrono::NaiveDate;
use gix::bstr::ByteSlice as _;

use super::types::{ChangedFile, CommitInfo, ObjectId};
use crate::commands::history::HistoryOptions;

const DEFAULT_BINARY_THRESHOLD: usize = 512 * 1024;
const BINARY_CHECK_LIMIT: usize = 8000;

pub struct LocalRepo {
    pub(super) inner: gix::Repository,
}

impl LocalRepo {
    #[must_use]
    pub fn staged_files(&self) -> Vec<PathBuf> {
        let Ok(index) = self.inner.index_or_empty() else {
            return Vec::new();
        };

        let Ok(head_tree_id) = self.inner.head_tree_id() else {
            return self.all_indexed_files(&index);
        };

        let Ok(head_tree) = self.inner.find_tree(head_tree_id) else {
            return Vec::new();
        };

        self.files_differing_from_tree(&index, &head_tree)
    }

    #[must_use]
    pub fn staged_content(&self, path: &Path) -> Option<String> {
        let index = self.inner.index_or_empty().ok()?;
        let path_str = path.to_str()?;

        let entry = index.entries().iter().find(|e| e.path(&index) == path_str)?;
        let blob_id = gix::ObjectId::from_bytes_or_panic(entry.id.as_bytes());

        self.read_blob_as_string(blob_id, None)
    }

    pub fn collect_commits(&self, opts: &HistoryOptions) -> anyhow::Result<Vec<ObjectId>> {
        let tips = self.resolve_walk_starting_points(opts)?;
        if tips.is_empty() {
            return Ok(Vec::new());
        }

        let mut walk = self
            .inner
            .rev_walk(tips)
            .sorting(gix::revision::walk::Sorting::ByCommitTime(Default::default()));

        if opts.first_parent {
            walk = walk.first_parent_only();
        }

        let stop_at = opts.since.as_ref().and_then(|since| self.resolve_ref(since).ok());

        let limit = opts.limit.unwrap_or(usize::MAX);
        let mut commits = Vec::with_capacity(limit.min(1024));

        for info in walk.all().context("failed to start revision walk")?.flatten() {
            if stop_at.is_some_and(|id| info.id == id) {
                break;
            }

            commits.push(ObjectId::from_raw(info.id));

            if commits.len() >= limit {
                break;
            }
        }

        Ok(commits)
    }

    #[must_use]
    pub fn commit_changes(&self, commit_id: ObjectId) -> Vec<ChangedFile> {
        let Ok(commit) = self.inner.find_commit(commit_id.into_raw()) else {
            return Vec::new();
        };

        let Ok(tree) = commit.tree() else {
            return Vec::new();
        };

        let parent_tree = self.first_parent_tree(&commit);
        let from_tree = parent_tree
            .as_ref()
            .map_or_else(|| self.inner.empty_tree(), |t| t.clone());

        self.diff_trees(&from_tree, &tree)
    }

    #[must_use]
    pub fn read_blob_as_text(&self, oid: ObjectId, max_bytes: Option<u64>) -> Option<String> {
        self.read_blob_as_string(oid.into_raw(), max_bytes)
    }

    #[must_use]
    pub fn commit_info(&self, oid: ObjectId) -> Option<CommitInfo> {
        self.inner
            .find_commit(oid.into_raw())
            .ok()
            .map(|c| CommitInfo::from_gix_commit(&c))
    }

    fn read_blob_as_string(&self, oid: gix::ObjectId, max_bytes: Option<u64>) -> Option<String> {
        let blob = self.inner.find_blob(oid).ok()?;

        if let Some(max) = max_bytes
            && blob.data.len() > max as usize
        {
            return None;
        }

        if self.is_binary_blob(&blob.data) {
            return None;
        }

        String::from_utf8(blob.data.to_vec()).ok()
    }

    fn is_binary_blob(&self, data: &[u8]) -> bool {
        let threshold = self
            .inner
            .big_file_threshold()
            .ok()
            .map(|t| t as usize)
            .unwrap_or(DEFAULT_BINARY_THRESHOLD);

        let check_len = data.len().min(threshold.min(BINARY_CHECK_LIMIT));
        data[..check_len].contains(&0)
    }

    fn resolve_walk_starting_points(&self, opts: &HistoryOptions) -> anyhow::Result<Vec<gix::ObjectId>> {
        if opts.until != "HEAD" {
            return self.resolve_single_ref(&opts.until);
        }

        if let Some(branch) = &opts.branch {
            return self.resolve_branch(branch);
        }

        self.resolve_all_local_branches()
    }

    fn resolve_single_ref(&self, reference: &str) -> anyhow::Result<Vec<gix::ObjectId>> {
        let oid = self
            .resolve_ref(reference)
            .map_err(|_| anyhow::anyhow!("cannot resolve --until ref '{}'", reference))?;
        Ok(vec![oid])
    }

    fn resolve_branch(&self, branch: &str) -> anyhow::Result<Vec<gix::ObjectId>> {
        let refname = format!("refs/heads/{branch}");
        let reference = self
            .inner
            .find_reference(&refname)
            .map_err(|_| anyhow::anyhow!("branch '{}' not found", branch))?;
        Ok(vec![reference.id().detach()])
    }

    fn resolve_all_local_branches(&self) -> anyhow::Result<Vec<gix::ObjectId>> {
        let mut tips = Vec::new();

        if let Ok(refs) = self.inner.references()
            && let Ok(locals) = refs.local_branches()
        {
            tips.extend(locals.flatten().map(|b| b.id().detach()));
        }

        if tips.is_empty()
            && let Ok(head) = self.inner.head_id()
        {
            tips.push(head.detach());
        }

        Ok(tips)
    }

    fn resolve_ref(&self, reference: &str) -> anyhow::Result<gix::ObjectId> {
        if let Ok(date) = NaiveDate::parse_from_str(reference, "%Y-%m-%d") {
            return self.find_commit_before_date(date);
        }

        self.inner
            .rev_parse_single(reference)
            .map(|obj| obj.detach())
            .map_err(|_| anyhow::anyhow!("cannot resolve '{}'", reference))
    }

    fn find_commit_before_date(&self, date: NaiveDate) -> anyhow::Result<gix::ObjectId> {
        let timestamp = date
            .and_hms_opt(23, 59, 59)
            .context("invalid date")?
            .and_local_timezone(chrono::Local)
            .single()
            .context("ambiguous local time")?
            .timestamp();

        let head = self.inner.head_id().context("no HEAD")?;

        for info in self.inner.rev_walk([head]).all()?.flatten() {
            let commit = self.inner.find_commit(info.id)?;
            if commit.time()?.seconds <= timestamp {
                return Ok(info.id);
            }
        }

        anyhow::bail!("no commits found on or before {date}")
    }

    fn first_parent_tree(&self, commit: &gix::Commit<'_>) -> Option<gix::Tree<'_>> {
        commit
            .parent_ids()
            .next()
            .and_then(|pid| self.inner.find_commit(pid).ok())
            .and_then(|pc| pc.tree().ok())
    }

    fn all_indexed_files(&self, index: &gix::worktree::Index) -> Vec<PathBuf> {
        index
            .entries()
            .iter()
            .map(|e| PathBuf::from(e.path(index).to_string()))
            .collect()
    }

    fn files_differing_from_tree(&self, index: &gix::worktree::Index, head_tree: &gix::Tree<'_>) -> Vec<PathBuf> {
        let null_oid = gix::ObjectId::null(self.inner.object_hash());

        index
            .entries()
            .iter()
            .filter_map(|entry| {
                let path = entry.path(index);
                let entry_id = gix::ObjectId::from_bytes_or_panic(entry.id.as_bytes());

                let head_id = head_tree
                    .lookup_entry_by_path(path.to_str_lossy().as_ref())
                    .ok()
                    .flatten()
                    .map(|e| e.object_id())
                    .unwrap_or(null_oid);

                (entry_id != head_id).then(|| PathBuf::from(path.to_string()))
            })
            .collect()
    }

    fn diff_trees(&self, from: &gix::Tree<'_>, to: &gix::Tree<'_>) -> Vec<ChangedFile> {
        let Ok(mut changes) = from.changes() else {
            return Vec::new();
        };

        let mut entries = Vec::new();

        let _ = changes.for_each_to_obtain_tree(to, |change| {
            use gix::object::tree::diff::Change;

            match change {
                Change::Addition { location, id, .. }
                | Change::Modification { location, id, .. }
                | Change::Rewrite { location, id, .. } => {
                    entries.push(ChangedFile {
                        path: PathBuf::from(location.to_str_lossy().into_owned()),
                        blob_id: ObjectId::from_raw(id.detach()),
                    });
                }
                Change::Deletion { .. } => {}
            }

            Ok::<_, std::convert::Infallible>(std::ops::ControlFlow::Continue(()))
        });

        entries
    }
}
