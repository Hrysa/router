use super::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard, RwLock};

const CONFIG_FILENAME: &str = "config.yml";

/// Thread-safe config store with atomic read/write and backup management.
pub struct ConfigStore {
    inner: Arc<RwLock<Config>>,
    operation: Mutex<()>,
    applied: RwLock<Config>,
    apply_state: crate::service::apply::ApplyState,
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
            applied: RwLock::new(config.clone()),
            apply_state: crate::service::apply::ApplyState::default(),
            inner: Arc::new(RwLock::new(config)),
            operation: Mutex::new(()),
            path,
            backup_dir,
        })
    }

    /// Get a clone of the current config.
    pub async fn get(&self) -> Config {
        self.inner.read().await.clone()
    }

    pub async fn lock_operation(&self) -> MutexGuard<'_, ()> {
        self.operation.lock().await
    }

    pub async fn get_applied(&self) -> Config {
        self.applied.read().await.clone()
    }

    pub fn apply_state(&self) -> &crate::service::apply::ApplyState {
        &self.apply_state
    }

    pub async fn mark_applied(&self, config: &Config) {
        *self.applied.write().await = config.clone();
    }

    /// Replace the entire config and write to disk atomically.
    pub async fn set(&self, config: Config) -> Result<()> {
        let errors = super::validator::validate(&config);
        if !errors.is_empty() {
            anyhow::bail!("config validation failed: {:?}", errors);
        }
        let mut current = self.inner.write().await;
        self.backup().await?;

        let yaml = serde_yaml::to_string(&config).context("failed to serialize config")?;

        // Atomic write: write to temp file, then rename
        crate::service::files::atomic_write(&self.path, yaml.as_bytes(), 0o600)?;

        *current = config;
        tracing::info!("config saved to {}", self.path.display());
        Ok(())
    }

    /// Create a timestamped backup of the current config file.
    pub async fn backup(&self) -> Result<PathBuf> {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S-%f");
        let backup_path =
            self.backup_dir
                .join(format!("{}-{}.yml", timestamp, uuid::Uuid::new_v4()));

        if self.path.exists() {
            let content = fs::read(&self.path)?;
            crate::service::files::atomic_write(&backup_path, &content, 0o600)
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

        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created));
        Ok(entries)
    }

    /// Restore config from a specific backup.
    pub async fn restore(&self, backup_id: &str) -> Result<Config> {
        if backup_id.is_empty()
            || !backup_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            anyhow::bail!("invalid backup ID");
        }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct TestStore {
        pub store: Arc<ConfigStore>,
        directory: PathBuf,
    }

    impl TestStore {
        pub fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("routerd-store-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            let config = Config::default();
            crate::service::files::atomic_write(
                &directory.join(CONFIG_FILENAME),
                serde_yaml::to_string(&config).unwrap().as_bytes(),
                0o600,
            )
            .unwrap();
            let store = Arc::new(ConfigStore::new(directory.to_str().unwrap()).unwrap());
            Self { store, directory }
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[tokio::test]
    async fn singbox_jsonc_round_trips_through_config_and_backups() {
        let fixture = TestStore::new();
        let initial = fixture.store.get().await;
        assert!(initial.singbox.is_none());
        let raw = "{\n  // preserve this comment\n  \"log\": { \"level\": \"info\" }\n}\n";
        let mut config = initial.clone();
        config.singbox = Some(super::super::schema::Singbox { config: raw.into() });
        fixture.store.set(config.clone()).await.unwrap();
        let reloaded = ConfigStore::new(fixture.directory.to_str().unwrap()).unwrap();
        assert_eq!(reloaded.get().await.singbox.unwrap().config, raw);
        assert_eq!(fixture.store.get_applied().await, initial);
        let backup = fixture.store.backup().await.unwrap();
        fixture.store.set(initial).await.unwrap();
        fixture
            .store
            .restore(backup.file_stem().unwrap().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(fixture.store.get().await, config);
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn empty_singbox_config_cannot_replace_saved_configuration() {
        let fixture = TestStore::new();
        let initial = fixture.store.get().await;
        let mut config = initial.clone();
        config.singbox = Some(super::super::schema::Singbox {
            config: "  \n".into(),
        });
        assert!(fixture.store.set(config).await.is_err());
        assert_eq!(fixture.store.get().await, initial);
    }

    #[tokio::test]
    async fn rapid_saves_keep_distinct_private_backups() {
        let fixture = TestStore::new();
        for index in 0..3 {
            let mut config = fixture.store.get().await;
            config.auth.jwt_secret = index.to_string();
            fixture.store.set(config).await.unwrap();
        }
        let backups = fixture.store.list_backups().unwrap();
        assert_eq!(backups.len(), 3);
        for entry in fs::read_dir(fixture.directory.join("backups")).unwrap() {
            assert_eq!(
                entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(&fixture.store.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let disk: Config =
            serde_yaml::from_str(&fs::read_to_string(&fixture.store.path).unwrap()).unwrap();
        assert_eq!(disk, fixture.store.get().await);
        assert_ne!(disk, fixture.store.get_applied().await);
    }

    #[tokio::test]
    async fn restore_validates_ids_and_creates_one_backup() {
        let fixture = TestStore::new();
        fixture.store.set(Config::default()).await.unwrap();
        let backup = fixture.store.list_backups().unwrap().remove(0);
        fixture.store.restore(&backup.id).await.unwrap();
        assert_eq!(fixture.store.list_backups().unwrap().len(), 2);
        for identifier in ["", "../config", "/etc/router/config", "..", "a/b"] {
            assert!(fixture.store.restore(identifier).await.is_err());
        }
    }

    #[tokio::test]
    async fn invalid_config_does_not_change_disk_or_memory() {
        let fixture = TestStore::new();
        let before = fixture.store.get().await;
        let mut invalid = before.clone();
        invalid.firewall.default_policy.input = "invalid".into();
        assert!(fixture.store.set(invalid).await.is_err());
        assert_eq!(fixture.store.get().await, before);
        assert!(fixture.store.list_backups().unwrap().is_empty());
    }
}
