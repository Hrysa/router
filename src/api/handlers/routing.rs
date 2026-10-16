use crate::api::{error::ApiError, server::AppState};
use crate::config::{
    schema::{Routing, StaticRoute},
    Config,
};
use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

pub async fn get_routing(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let config = state.config.get().await;
    let wans = crate::config::routing::wan_return_routes(&config)?;
    Ok(Json(json!({
        "routes": config.routing.routes,
        "wan_tables": wans.iter().map(|wan| json!({"name": wan.name, "interface": wan.interface, "table": wan.table})).collect::<Vec<_>>()
    })))
}

pub async fn replace_routing(
    State(state): State<AppState>,
    Json(routing): Json<Routing>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    config.routing = routing;
    save(&state, config).await
}

pub async fn create_route(
    State(state): State<AppState>,
    Json(mut route): Json<StaticRoute>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    route.id = config
        .routing
        .routes
        .iter()
        .map(|route| route.id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| ApiError::Conflict("route ID space exhausted".into()))?;
    config.routing.routes.push(route.clone());
    let _ = save(&state, config).await?;
    Ok(Json(json!({"status": "ok", "route": route})))
}

pub async fn update_route(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(route): Json<StaticRoute>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    if route.id != id {
        return Err(ApiError::BadRequest("route ID cannot be changed".into()));
    }
    let existing = config
        .routing
        .routes
        .iter_mut()
        .find(|route| route.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("route {id} not found")))?;
    *existing = route;
    save(&state, config).await
}

pub async fn delete_route(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    let length = config.routing.routes.len();
    config.routing.routes.retain(|route| route.id != id);
    if config.routing.routes.len() == length {
        return Err(ApiError::NotFound(format!("route {id} not found")));
    }
    save(&state, config).await
}

pub async fn live_routes() -> Result<Json<Value>, ApiError> {
    Ok(Json(crate::service::routing::live_routes().await?))
}

async fn save(state: &AppState, config: Config) -> Result<Json<Value>, ApiError> {
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{static_routes::test_route, store::tests::TestStore};

    #[tokio::test]
    async fn concurrent_creates_get_unique_ids_and_preserve_other_config() {
        let fixture = TestStore::new();
        let config = crate::config::routing::test_config();
        fixture.store.set(config.clone()).await.unwrap();
        let state = crate::api::handlers::auth::tests::state(fixture.store.clone());
        let mut second = test_route();
        second.destination = "198.51.100.10".into();
        let (one, two) = tokio::join!(
            create_route(State(state.clone()), Json(test_route())),
            create_route(State(state.clone()), Json(second))
        );
        assert!(one.is_ok() && two.is_ok());
        let saved = fixture.store.get().await;
        assert_eq!(saved.routing.routes.len(), 2);
        assert_ne!(saved.routing.routes[0].id, saved.routing.routes[1].id);
        assert_eq!(saved.firewall, config.firewall);
        assert_eq!(saved.interfaces, config.interfaces);
        let Json(list) = get_routing(State(state.clone())).await.unwrap();
        assert_eq!(list["routes"].as_array().unwrap().len(), 2);
        assert_eq!(list["wan_tables"][0]["table"], 100);
        assert!(matches!(
            crate::api::handlers::config::delete_interface(
                State(state.clone()),
                Path("wan0".into())
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        assert_eq!(fixture.store.get().await, saved);
        // Save never publishes an applied snapshot or executes a host command.
        assert!(fixture.store.get_applied().await.routing.routes.is_empty());
        let mut invalid = saved.routing.routes[0].clone();
        invalid.gateway = Some("::1".into());
        assert!(matches!(
            update_route(State(state.clone()), Path(invalid.id), Json(invalid)).await,
            Err(ApiError::Validation(_))
        ));
        assert_eq!(fixture.store.get().await, saved);
        let _ = delete_route(State(state.clone()), Path(saved.routing.routes[0].id))
            .await
            .unwrap();
        assert_eq!(fixture.store.get().await.routing.routes.len(), 1);
        let mut orphan = fixture.store.get().await.routing;
        orphan.routes[0].interface = "missing".into();
        assert!(replace_routing(State(state), Json(orphan)).await.is_err());
    }
}
