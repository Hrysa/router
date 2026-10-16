use anyhow::Result;
use std::path::Path;

use crate::config::ConfigStore;
use crate::service::apply;
use crate::service::manager::ServiceManager;

/// Rollback to the most recent backup.
pub async fn rollback(
    config_store: &ConfigStore,
    config_path: &Path,
    service_manager: &ServiceManager,
) -> Result<apply::ApplyResult> {
    // Get list of backups
    let backups = config_store.list_backups()?;

    if backups.is_empty() {
        anyhow::bail!("no backups available for rollback");
    }

    // Get previous config before restoring
    let prev_config = config_store.get_applied().await;

    // Restore the most recent backup
    let latest = &backups[0];
    tracing::info!(backup_id = %latest.id, "rolling back to backup");

    let config = config_store.restore(&latest.id).await?;

    // Apply the restored config (force=true to apply all services)
    let result = apply::apply(
        &config,
        &prev_config,
        config_path,
        service_manager,
        config_store.apply_state(),
        true,
    )
    .await?;
    config_store.mark_applied(&config).await;

    tracing::info!("rollback completed successfully");
    Ok(result)
}

/// Rollback to a specific backup by ID.
pub async fn rollback_to(
    backup_id: &str,
    config_store: &ConfigStore,
    config_path: &Path,
    service_manager: &ServiceManager,
) -> Result<apply::ApplyResult> {
    tracing::info!(backup_id = %backup_id, "rolling back to specific backup");

    // Get previous config before restoring
    let prev_config = config_store.get_applied().await;

    let config = config_store.restore(backup_id).await?;
    let result = apply::apply(
        &config,
        &prev_config,
        config_path,
        service_manager,
        config_store.apply_state(),
        true,
    )
    .await?;
    config_store.mark_applied(&config).await;

    tracing::info!("rollback to {} completed successfully", backup_id);
    Ok(result)
}
