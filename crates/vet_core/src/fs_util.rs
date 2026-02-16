use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// Writes `content` to `path` atomically by writing to a temporary file
/// first, syncing to disk, then renaming into place.
pub fn atomic_write(path: &Path, content: &str) -> io::Result<()> {
    let temp_path = path.with_extension("tmp");

    let mut file = File::create(&temp_path)?;
    file.write_all(content.as_bytes())?;

    // Ensure data is persisted to disk before rename
    file.sync_all()?;

    // Drop file handle before rename (Windows compatibility)
    drop(file);

    fs::rename(&temp_path, path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_new_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("vet_atomic_write_test_new.txt");

        // Ensure clean state
        let _ = fs::remove_file(&test_file);

        atomic_write(&test_file, "test content").unwrap();

        let content = fs::read_to_string(&test_file).unwrap();
        assert_eq!(content, "test content");

        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn atomic_write_replaces_existing_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("vet_atomic_write_test_existing.txt");

        // Create initial file
        fs::write(&test_file, "old content").unwrap();

        // Atomically replace it
        atomic_write(&test_file, "new content").unwrap();

        let content = fs::read_to_string(&test_file).unwrap();
        assert_eq!(content, "new content");

        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn atomic_write_does_not_leave_temp_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("vet_atomic_write_test_cleanup.txt");
        let temp_file = test_file.with_extension("tmp");

        // Ensure clean state
        let _ = fs::remove_file(&test_file);
        let _ = fs::remove_file(&temp_file);

        atomic_write(&test_file, "content").unwrap();

        // Temp file should not exist after successful write
        assert!(!temp_file.exists());
        assert!(test_file.exists());

        fs::remove_file(&test_file).unwrap();
    }
}
