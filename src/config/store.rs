use super::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

const CONFIG_FILENAME: &str = "config.yml";

/// Thread-safe config store with atomic read/write and backup management.
pub struct ConfigStore {
    inner: Arc<RwLock<Config>>,
    path: PathBuf,
    backup_dir: PathBuf,
}

impl ConfigStore {
    /// Load config from a directory. Reads `<dir>/config.yml`.
    /// Creates backup directory at `<dir>/backups/`.
    pub fn new(config_dir: &str) -> Result<Self> {
        let dir = PathBuf::from(config_dir);
        let path = dir.join(CONFIG_FILENAME);
        let backup_dir = dir.join("backups");

        // Ensure backup directory exists
        fs::create_dir_all(&backup_dir)
            .with_context(|| format!("failed to create backup dir: {}", backup_dir.display()))?;

        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse config: {}", path.display()))?;

        Ok(Self {
            inner: Arc::new(RwLock::new(config)),
            path,
            backup_dir,
        })
    }

    /// Get a clone of the current config.
    pub async fn get(&self) -> Config {
        self.inner.read().await.clone()
    }

    /// Replace the entire config and write to disk atomically.
    pub async fn set(&self, config: Config) -> Result<()> {
        self.backup().await?;

        let yaml = serde_yaml::to_string(&config).context("failed to serialize config")?;

        // Atomic write: write to temp file, then rename
        let tmp_path = self.path.with_extension("yml.tmp");
        fs::write(&tmp_path, &yaml)
            .with_context(|| format!("failed to write config: {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &self.path)
            .with_context(|| format!("failed to rename config: {}", self.path.display()))?;

        *self.inner.write().await = config;
        tracing::info!("config saved to {}", self.path.display());
        Ok(())
    }

    /// Create a timestamped backup of the current config file.
    pub async fn backup(&self) -> Result<PathBuf> {
        let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let backup_path = self.backup_dir.join(format!("{}.yml", timestamp));

        if self.path.exists() {
            fs::copy(&self.path, &backup_path)
                .with_context(|| format!("failed to backup to: {}", backup_path.display()))?;
            tracing::info!("config backed up to {}", backup_path.display());
        }

        Ok(backup_path)
    }

    /// List available backups, newest first.
    pub fn list_backups(&self) -> Result<Vec<BackupEntry>> {
        let mut entries: Vec<BackupEntry> = fs::read_dir(&self.backup_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yml" || ext == "yaml")
                    .unwrap_or(false)
            })
            .filter_map(|e| {
                let path = e.path();
                let name = path.file_stem()?.to_str()?.to_string();
                let meta = e.metadata().ok()?;
                Some(BackupEntry {
                    id: name.clone(),
                    size: meta.len(),
                    created: chrono::DateTime::from(meta.modified().ok()?),
                })
            })
            .collect();

        entries.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(entries)
    }

    /// Restore config from a specific backup.
    pub async fn restore(&self, backup_id: &str) -> Result<Config> {
        // Try both .yml and .yaml extensions
        let backup_path = if self.backup_dir.join(format!("{}.yml", backup_id)).exists() {
            self.backup_dir.join(format!("{}.yml", backup_id))
        } else {
            self.backup_dir.join(format!("{}.yaml", backup_id))
        };

        if !backup_path.exists() {
            anyhow::bail!("backup not found: {}", backup_id);
        }

        let content = fs::read_to_string(&backup_path)
            .with_context(|| format!("failed to read backup: {}", backup_path.display()))?;
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse backup: {}", backup_path.display()))?;

        // Backup current before restoring
        self.backup().await?;

        // Write restored config
        self.set(config.clone()).await?;

        tracing::info!("config restored from backup: {}", backup_id);
        Ok(config)
    }

}

#[derive(Debug, Clone)]
pub struct BackupEntry {
    pub id: String,
    pub size: u64,
    pub created: chrono::DateTime<chrono::Local>,
}
