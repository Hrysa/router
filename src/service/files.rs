use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct StagedFile {
    path: PathBuf,
}

pub struct StagedDirectory {
    path: PathBuf,
}

impl StagedDirectory {
    pub fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("routerd-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl StagedFile {
    pub fn new(directory: &Path, content: &[u8], mode: u32) -> Result<Self> {
        let path = directory.join(format!(".routerd-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to create staged file in {}", directory.display()))?;
        let staged = Self { path };
        file.write_all(content)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        Ok(staged)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn atomic_write(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staged = StagedFile::new(parent, content, mode)?;
    std::fs::rename(staged.path(), path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_files_are_private_unique_and_removed() {
        let first = StagedFile::new(&std::env::temp_dir(), b"secret", 0o600).unwrap();
        let second = StagedFile::new(&std::env::temp_dir(), b"other", 0o600).unwrap();
        let first_path = first.path().to_path_buf();
        assert_ne!(first.path(), second.path());
        assert_eq!(
            std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(first);
        assert!(!first_path.exists());
    }

    #[test]
    fn atomic_write_replaces_symlink_without_touching_target() {
        let target = StagedFile::new(&std::env::temp_dir(), b"original", 0o600).unwrap();
        let destination =
            std::env::temp_dir().join(format!("routerd-test-{}", uuid::Uuid::new_v4()));
        std::os::unix::fs::symlink(target.path(), &destination).unwrap();
        atomic_write(&destination, b"replacement", 0o600).unwrap();
        assert_eq!(std::fs::read(target.path()).unwrap(), b"original");
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
        std::fs::remove_file(destination).unwrap();
    }
}
