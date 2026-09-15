//! Admin API — health, route management.
//!
//! Always available on the configured `addr`, regardless of push/pull mode.
//! IP access restricted via `admin_allowed_ips` in config.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Instant;

use crate::config::BridgeConfig;
use crate::router::ProfileRouter;

/// Application state shared across admin handlers.
#[derive(Clone)]
pub struct AdminState {
    pub router: Arc<ProfileRouter>,
    pub config: BridgeConfig,
    pub startup: std::time::Instant,
}

/// Build the axum Router for admin endpoints.
pub fn build_admin_router(config: &BridgeConfig, router: Arc<ProfileRouter>) -> Router {
    let allowed = parse_ip_list(&config.admin_allowed_ips);
    let state = AdminState {
        router,
        config: config.clone(),
        startup: Instant::now(),
    };

    let admin_routes = Router::new()
        .route("/health", get(health))
        .route("/api/v1/routes", get(list_routes).post(create_route))
        .route("/api/v1/routes/{email}", delete(delete_route));

    // IP whitelist middleware for admin endpoints
    if !allowed.is_empty() {
        Router::new()
            .nest("/", admin_routes)
            .layer(middleware::from_fn_with_state(allowed.clone(), check_admin_ip))
            .with_state(state)
    } else {
        Router::new()
            .nest("/", admin_routes)
            .with_state(state)
    }
}

/// Parse IP/CIDR list from config strings (shared impl in security.rs).
fn parse_ip_list(raw: &[String]) -> Vec<(std::net::IpAddr, u8)> {
    raw.iter().filter_map(|s| crate::security::parse_cidr(s)).collect()
}

/// Middleware: reject requests from IPs not in the admin allowlist.
async fn check_admin_ip(
    State(allowed): State<Vec<(std::net::IpAddr, u8)>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, StatusCode> {
    let addr = req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    if allowed.is_empty() || allowed.iter().any(|&(net, pfx)| crate::security::ip_matches(addr, net, pfx)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// ── Response types ──────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
    version: &'static str,
}

#[derive(Serialize)]
struct RouteEntry {
    email: String,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct CreateRouteBody {
    email: String,
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct CreateRouteResponse {
    status: String,
    webhook_url: String,
}

// ── Handlers ────────────────────────────────────────────────

async fn health(State(state): State<AdminState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.startup.elapsed().as_secs(),
        version: concat!(env!("CARGO_PKG_VERSION"), "+", env!("GIT_COMMIT_HASH")),
    })
}

async fn list_routes(State(state): State<AdminState>) -> impl IntoResponse {
    let routes: Vec<RouteEntry> = state.router.list_routes().into_iter().map(|r| RouteEntry {
        email: r.email,
        host: r.host,
        port: r.port,
    }).collect();
    Json(routes)
}

async fn create_route(
    State(state): State<AdminState>,
    Json(body): Json<CreateRouteBody>,
) -> impl IntoResponse {
    if body.email.is_empty() || body.host.is_empty() || body.port == 0 {
        return (StatusCode::BAD_REQUEST, "email, host, and port are required").into_response();
    }
    state.router.update_route(&body.email, &body.host, body.port);
    tracing::info!(email = %body.email, host = %body.host, port = body.port, "Route created via API");

    let webhook_url = if state.config.mode == "push" {
        let host = state.config.hostname.as_deref().unwrap_or(&state.config.bind);
        format!("http://{}/webhooks/aimail-inbound", host)
    } else {
        String::new()
    };

    (StatusCode::OK, Json(CreateRouteResponse {
        status: "ok".to_string(),
        webhook_url,
    })).into_response()
}

async fn delete_route(
    State(state): State<AdminState>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    state.router.remove_route(&email);
    tracing::info!(email = %email, "Route deleted via API");
    (StatusCode::OK, "ok").into_response()
}
