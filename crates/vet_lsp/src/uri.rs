use std::path::PathBuf;

use tower_lsp::lsp_types::{InitializeParams, Url};

#[must_use]
pub fn try_uri_to_path(uri: &Url) -> Option<PathBuf> {
    uri.to_file_path().ok()
}

#[must_use]
pub fn extract_workspace_roots(params: &InitializeParams) -> Vec<PathBuf> {
    if let Some(folders) = &params.workspace_folders {
        let roots: Vec<PathBuf> = folders.iter().filter_map(|f| try_uri_to_path(&f.uri)).collect();

        if !roots.is_empty() {
            return roots;
        }
    }

    if let Some(root_uri) = &params.root_uri
        && let Some(path) = try_uri_to_path(root_uri)
    {
        return vec![path];
    }

    Vec::new()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use tower_lsp::lsp_types::{InitializeParams, Url, WorkspaceFolder};

    use super::*;

    #[cfg(windows)]
    mod test_uris {
        pub const PROJECT: &str = "file:///C:/Users/user/project";
        pub const PROJECT1: &str = "file:///C:/Users/user/project1";
        pub const PROJECT2: &str = "file:///C:/Users/user/project2";
        pub const MAIN_RS: &str = "file:///C:/Users/user/project/src/main.rs";
    }

    #[cfg(not(windows))]
    mod test_uris {
        pub const PROJECT: &str = "file:///home/user/project";
        pub const PROJECT1: &str = "file:///home/user/project1";
        pub const PROJECT2: &str = "file:///home/user/project2";
        pub const MAIN_RS: &str = "file:///home/user/project/src/main.rs";
    }

    #[test]
    fn try_uri_to_path_valid_file_uri() {
        let uri = Url::parse(test_uris::MAIN_RS).unwrap();
        let path = try_uri_to_path(&uri);

        let path = path.expect("should parse file URI");
        assert!(path.ends_with("main.rs"));
    }

    #[test]
    fn try_uri_to_path_returns_none_for_http() {
        let uri = Url::parse("https://example.com/file.rs").unwrap();
        let path = try_uri_to_path(&uri);

        assert!(path.is_none());
    }

    #[test]
    fn try_uri_to_path_returns_none_for_custom_scheme() {
        let uri = Url::parse("untitled:Untitled-1").unwrap();
        let path = try_uri_to_path(&uri);

        assert!(path.is_none());
    }

    #[test]
    fn extract_workspace_roots_from_folders() {
        let params = InitializeParams {
            workspace_folders: Some(vec![
                WorkspaceFolder {
                    uri: Url::parse(test_uris::PROJECT1).unwrap(),
                    name: "project1".into(),
                },
                WorkspaceFolder {
                    uri: Url::parse(test_uris::PROJECT2).unwrap(),
                    name: "project2".into(),
                },
            ]),
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert_eq!(roots.len(), 2);
    }

    #[test]
    fn extract_workspace_roots_falls_back_to_root_uri() {
        let params = InitializeParams {
            workspace_folders: None,
            root_uri: Some(Url::parse(test_uris::PROJECT).unwrap()),
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn extract_workspace_roots_empty_folders_falls_back() {
        let params = InitializeParams {
            workspace_folders: Some(vec![]),
            root_uri: Some(Url::parse(test_uris::PROJECT).unwrap()),
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn extract_workspace_roots_skips_non_file_uris() {
        let params = InitializeParams {
            workspace_folders: Some(vec![
                WorkspaceFolder {
                    uri: Url::parse(test_uris::PROJECT).unwrap(),
                    name: "project".into(),
                },
                WorkspaceFolder {
                    uri: Url::parse("https://example.com/remote").unwrap(),
                    name: "remote".into(),
                },
            ]),
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn extract_workspace_roots_returns_empty_when_nothing_valid() {
        let params = InitializeParams {
            workspace_folders: None,
            root_uri: None,
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert!(roots.is_empty());
    }

    #[test]
    fn extract_workspace_roots_non_file_root_uri_returns_empty() {
        let params = InitializeParams {
            workspace_folders: None,
            root_uri: Some(Url::parse("https://example.com/project").unwrap()),
            ..Default::default()
        };

        let roots = extract_workspace_roots(&params);

        assert!(roots.is_empty());
    }
}
