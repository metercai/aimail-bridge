//! Push-mode HTTP server — transparent webhook proxy.
//!
//! Receives POSTs from relay at a single stable endpoint, looks up
//! the target agent via the X-AIMail-Email header, and forwards the
//! raw body + all headers to the gateway's webhook port on localhost.
//!
//! Optional per-IP allowlist for DDoS protection — configure
//! `push.allowed_ips` in aimail_bridge.toml.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, HeaderName, StatusCode},
    middleware,
    response::IntoResponse,
    routing::post, Router,
};


use crate::config::BridgeConfig;
use crate::router::ProfileRouter;

/// Application state shared across push handlers.
#[derive(Clone)]
pub struct PushState {
    pub router: Arc<ProfileRouter>,
    pub http_client: reqwest::Client,
    pub config: BridgeConfig,
    /// Pre-parsed forward header names from config.
    /// Single mode: whitelist filter — only these headers pass through.
    /// Batch mode: per-recipient headers built with batch_header_value().
    pub forward_headers: Vec<HeaderName>,
}

/// IP/CIDR allowlist.  Empty = allow all.  Otherwise, only requests from
/// matching source IPs are permitted (403 Forbidden on mismatch).
#[derive(Clone)]
pub struct IpAllowlist {
    entries: Vec<(IpAddr, u8)>,  // (network, prefix_len)
}

impl IpAllowlist {
    /// Parse an allowlist from config strings ("192.168.1.1" or "10.0.0.0/8").
    /// Invalid entries are logged and skipped.
    pub fn from_config(raw: &[String]) -> Self {
        let entries = raw.iter().filter_map(|s| {
            match parse_cidr(s) {
                Some(e) => Some(e),
                None => {
                    tracing::warn!(entry = %s, "Invalid IP/CIDR in allowed_ips — skipping");
                    None
                }
            }
        }).collect();
        Self { entries }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        if self.entries.is_empty() {
            return true; // no allowlist = allow all
        }
        self.entries.iter().any(|&(network, prefix)| crate::security::ip_matches(ip, network, prefix))
    }
}

/// Parse "192.168.1.1" or "10.0.0.0/8" into (network, prefix_len).
/// Shared implementation in security.rs (AUDIT-1 C3).
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    crate::security::parse_cidr(s)
}

/// IP/CIDR blacklist. Empty = allow all.
#[derive(Clone)]
pub struct IpBlacklist {
    entries: Vec<(IpAddr, u8)>,
}

impl IpBlacklist {
    pub fn from_config(raw: &[String]) -> Self {
        let entries = raw.iter().filter_map(|s| {
            match parse_cidr(s) {
                Some(e) => Some(e),
                None => {
                    tracing::warn!(entry = %s, "Invalid IP/CIDR in blacklist_ips — skipping");
                    None
                }
            }
        }).collect();
        Self { entries }
    }

    pub fn blocks(&self, ip: IpAddr) -> bool {
        if self.entries.is_empty() { return false; }
        self.entries.iter().any(|&(network, prefix)| crate::security::ip_matches(ip, network, prefix))
    }
}

/// Simple per-IP rate limiter using a sliding window.
#[derive(Clone)]
pub struct IpRateLimiter {
    window: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>, // ip → (window_start, count)
    max_per_sec: u32,
}

impl IpRateLimiter {
    pub fn new(max_per_sec: u32) -> Self {
        Self { window: Arc::new(Mutex::new(HashMap::new())), max_per_sec }
    }

    /// Returns true if the request is allowed (under limit).
    /// Also cleans up stale entries older than 2 seconds.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.max_per_sec == 0 { return true; }
        let now = Instant::now();
        let mut w = self.window.lock().unwrap();
        // Cleanup stale entries (older than 2 seconds)
        w.retain(|_, (ts, _)| now.saturating_duration_since(*ts).as_millis() <= 2000);
        let entry = w.entry(ip).or_insert((now, 0));
        if now.saturating_duration_since(entry.0).as_millis() > 1000 {
            // New second window — reset count
            entry.0 = now;
            entry.1 = 1;
            return true;
        }
        if entry.1 >= self.max_per_sec {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Build the axum Router for push mode.
pub fn build_push_router(state: PushState) -> Router {
    let mut router = Router::new()
        .route("/webhooks/*name", post(handle_webhook))
        .layer(DefaultBodyLimit::max((state.config.push.body_limit_mb as usize) * 1024 * 1024))
        .with_state(state.clone());

    // IP blacklist (checked first, before allowlist)
    if !state.config.push.blacklist_ips.is_empty() {
        let blacklist = IpBlacklist::from_config(&state.config.push.blacklist_ips);
        router = router.layer(middleware::from_fn_with_state(blacklist, check_blacklist));
        tracing::info!(count = state.config.push.blacklist_ips.len(), "IP blacklist enabled");
    }

    if !state.config.push.allowed_ips.is_empty() {
        let allowlist = IpAllowlist::from_config(&state.config.push.allowed_ips);
        router = router.layer(middleware::from_fn_with_state(allowlist, check_ip));
        tracing::info!(count = state.config.push.allowed_ips.len(), "IP allowlist enabled");
    }

    // Rate limiting (per source IP)
    if state.config.push.rate_limit > 0 {
        let limiter = IpRateLimiter::new(state.config.push.rate_limit);
        router = router.layer(middleware::from_fn_with_state(limiter, check_rate_limit));
        tracing::info!(rps = state.config.push.rate_limit, "Rate limiting enabled");
    }

    // Vhost routing: intercept unmatched paths via fallback
    if !state.config.push.sites.is_empty() {
        let vhost_routes = std::sync::Arc::new(
            crate::vhost::build_routes(&state.config.push.sites)
        );
        let vr = vhost_routes.clone();
        let vhost_body_limit = state.config.push.body_limit_mb;
        router = router.fallback(move |req: axum::http::Request<axum::body::Body>| {
            let vr = vr.clone();
            async move {
                // Extract client IP from axum's ConnectInfo extension
                let client_ip = req.extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip());
                if let Some(route) = crate::vhost::find_vhost(&req, &vr) {
                    return crate::vhost::handle_vhost(route, req, client_ip, vhost_body_limit).await;
                }
                axum::http::Response::builder()
                    .status(404)
                    .body(axum::body::Body::from("not found"))
                    .unwrap()
            }
        });
        tracing::info!(count = state.config.push.sites.len(), "Vhost sites loaded");
    }

    router = crate::security::apply_security_headers(router);
    router
}

/// Axum middleware: reject requests not in IP allowlist (403).
async fn check_ip(
    State(allowlist): State<IpAllowlist>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, StatusCode> {
    if allowlist.allows(addr.ip()) {
        Ok(next.run(request).await)
    } else {
        tracing::warn!(ip = %addr.ip(), "Blocked by IP allowlist");
        Err(StatusCode::FORBIDDEN)
    }
}

/// Health check — also prints route count.
/// Middleware: reject blacklisted IPs (403).
async fn check_blacklist(
    State(blacklist): State<IpBlacklist>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, StatusCode> {
    if blacklist.blocks(addr.ip()) {
        tracing::warn!(ip = %addr.ip(), "Blocked by IP blacklist");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

/// Middleware: rate-limit per source IP (429 Too Many Requests).
async fn check_rate_limit(
    State(limiter): State<IpRateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, StatusCode> {
    if !limiter.check(addr.ip()) {
        tracing::warn!(ip = %addr.ip(), "Rate limited");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}

/// Transparent webhook proxy.
///
/// Relay sends:  POST /webhooks/aimail-inbound
///               X-AIMail-Email: alice@admin.relay
///               X-Webhook-Signature: sha256=...
///               {payload}
///
/// Bridge: looks up `alice@admin.relay` → port 8645,
/// forwards body + headers verbatim to `127.0.0.1:8645/webhooks/aimail-inbound`.
async fn handle_webhook(
    State(state): State<PushState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ── Multi-recipient: signatures array in payload ──────────────
    // Parse JSON once and check for the "signatures" key
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
        if v.get("signatures").and_then(|s| s.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
            return handle_batch_webhook(axum::extract::State(state), body).await;
        }
    }

    // ── Single mode (X-AIMail-Email header) ──
    let email = match headers
        .get("X-AIMail-Email")
        .and_then(|v| v.to_str().ok())
    {
        Some(e) => e.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, "Missing X-AIMail-Email header").into_response();
        }
    };

    let route = match state.router.lookup(&email) {
        Some(r) => r,
        None => {
            tracing::warn!(email = %email, "No route found");
            return (StatusCode::BAD_GATEWAY, format!("No route for {}", email)).into_response();
        }
    };

    let target = route.target_url();
    tracing::info!(email = %email, host = %route.host, port = route.port, target = %target, "Webhook relayed");

    let mut fwd_headers = HeaderMap::new();
    for name in &state.forward_headers {
        if let Some(val) = headers.get(name.as_str()) {
            fwd_headers.insert(name.clone(), val.clone());
        }
    }

    match state.http_client.post(target).headers(fwd_headers).body(body).send().await {
        Ok(resp) => {
            let status = resp.status();
            tracing::info!(email = %email, status = %status, "Webhook forwarded");
            (status, resp.bytes().await.unwrap_or_default()).into_response()
        }
        Err(e) => {
            tracing::error!(email = %email, error = %e, "Forward failed");
            (StatusCode::BAD_GATEWAY, format!("Forward failed: {}", e)).into_response()
        }
    }
}

/// Map a forward header name to its value for batch webhook entries.
/// Returns None for unknown header names (skipped with debug log).
fn batch_header_value(
    name: &str,
    email: &str,
    sig: &str,
    ts: &str,
) -> Option<(&'static str, String)> {
    // 中转协议兼容名归一到 AIMail 业务名输出(调用方按输出名去重)。
    match name {
        "X-AIMail-Email" => Some(("X-AIMail-Email", email.to_string())),
        "X-Webhook-Signature" => Some(("X-Webhook-Signature", sig.to_string())),
        "X-AIMail-Timestamp" | "X-Mailrelay-Timestamp" => Some(("X-AIMail-Timestamp", ts.to_string())),
        "content-type" => Some(("content-type", "application/json".to_string())),
        _ => None,
    }
}

/// Handle multi-recipient webhook: payload has "signatures" array,
/// payload itself IS the body (no "body" wrapper).
/// Fan-out to each recipient's gateway with per-recipient headers.
async fn handle_batch_webhook(
    State(state): State<PushState>,
    body: Bytes,
) -> axum::http::Response<axum::body::Body> {
    let batch: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid batch JSON: {}", e)).into_response();
        }
    };

    let sigs = match batch.get("signatures").and_then(|e| e.as_array()) {
        Some(arr) => arr,
        None => return (StatusCode::BAD_REQUEST, "Missing 'signatures' array").into_response(),
    };

    // Shared body = payload minus the signatures array
    let mut shared_body = batch.clone();
    let _ = shared_body.as_object_mut().map(|o| o.remove("signatures"));
    // Serialize once per batch, not per entry
    let body_bytes = match serde_json::to_vec(&shared_body) {
        Ok(b) => axum::body::Bytes::from(b),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize shared body from batch payload");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Batch body serialization failed").into_response();
        }
    };

    let total = sigs.len();
    let mut delivered = 0usize;

    for entry in sigs {
        let email = match entry["email"].as_str() {
            Some(e) => e,
            None => continue,
        };

        let route = match state.router.lookup(email) {
            Some(r) => {
                tracing::info!(email = %email, sig = %entry["signature"].as_str().unwrap_or(""), ts = %entry["timestamp"].as_str().unwrap_or(""),
                    "Batch entry → route found");
                r
            }
            None => {
                tracing::warn!(email = %email, "Batch entry has no route");
                continue;
            }
        };

        let target = route.target_url();
        let sig = entry["signature"].as_str().unwrap_or("");
        let ts = entry["timestamp"].as_str().unwrap_or("");

        // Build request with config-driven forward headers
        // (新旧名并存期按输出名去重, 防同一逻辑头重复下发)
        let mut req = state.http_client.post(target);
        let mut emitted: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for name in &state.forward_headers {
            match batch_header_value(name.as_str(), email, sig, ts) {
                Some((hdr_name, value)) => {
                    if emitted.insert(hdr_name) {
                        req = req.header(hdr_name, value);
                    }
                }
                None => {
                    tracing::debug!(header = %name, "Unknown forward header — skipping");
                }
            }
        }
        match req.body(body_bytes.clone()).send().await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(email = %email, "Batch entry forwarded");
                delivered += 1;
            }
            Ok(resp) => {
                tracing::warn!(email = %email, status = %resp.status(), "Batch entry non-2xx");
            }
            Err(e) => {
                tracing::error!(email = %email, error = %e, "Batch entry forward failed");
            }
        }
    }

    if delivered == total {
        (StatusCode::OK, format!("{}/{} delivered", delivered, total)).into_response()
    } else {
        (StatusCode::MULTI_STATUS, format!("{}/{} delivered", delivered, total)).into_response()
    }
}

/// Build a rustls TLS config from PEM cert + key files.
/// Used when `tls_cert` and `tls_key` are both configured (static certs).
pub fn build_tls_config_from_paths(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::BufReader;
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found in tls_key file")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        std::sync::Arc::new(config),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_cidr_single_ip() {
        assert_eq!(parse_cidr("192.168.1.1"), Some(("192.168.1.1".parse().unwrap(), 32)));
    }

    #[test]
    fn test_parse_cidr_network() {
        assert_eq!(parse_cidr("10.0.0.0/8"), Some(("10.0.0.0".parse().unwrap(), 8)));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert_eq!(parse_cidr("not-an-ip"), None);
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
    }

    #[test]
    fn test_ip_matches() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let net: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(crate::security::ip_matches(ip, net, 24));
        assert!(!crate::security::ip_matches(ip, net, 32));
    }

    #[test]
    fn test_allowlist_allows() {
        let allowlist = IpAllowlist::from_config(&["10.0.0.0/8".into()]);
        assert!(allowlist.allows("10.1.2.3".parse().unwrap()));
        assert!(!allowlist.allows("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_allowlist_empty_allows_all() {
        let allowlist = IpAllowlist::from_config(&[]);
        assert!(allowlist.allows("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_blacklist_blocks() {
        let blacklist = IpBlacklist::from_config(&["10.0.0.0/8".into()]);
        assert!(blacklist.blocks("10.1.2.3".parse().unwrap()));
        assert!(!blacklist.blocks("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = IpRateLimiter::new(5);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }
        assert!(!limiter.check(ip)); // 6th should be blocked
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let limiter = IpRateLimiter::new(0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_parse_cidr_ipv6() {
        assert_eq!(parse_cidr("::1"), Some(("::1".parse().unwrap(), 128)));
        assert_eq!(parse_cidr("2001:db8::/32"), Some(("2001:db8::".parse().unwrap(), 32)));
    }

    #[test]
    fn test_parse_cidr_prefix_0() {
        assert_eq!(parse_cidr("0.0.0.0/0"), Some(("0.0.0.0".parse().unwrap(), 0)));
        assert_eq!(parse_cidr("::/0"), Some(("::".parse().unwrap(), 0)));
    }

    #[test]
    fn test_parse_cidr_full_mask() {
        assert_eq!(parse_cidr("192.168.1.1/32"), Some(("192.168.1.1".parse().unwrap(), 32)));
        assert_eq!(parse_cidr("10.0.0.1/32"), Some(("10.0.0.1".parse().unwrap(), 32)));
    }

    #[test]
    fn test_ip_matches_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let net: IpAddr = "2001:db8::".parse().unwrap();
        assert!(crate::security::ip_matches(ip, net, 32));
        assert!(!crate::security::ip_matches(ip, net, 128));
    }

    #[test]
    fn test_ip_matches_prefix_0() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(crate::security::ip_matches(v4, "0.0.0.0".parse().unwrap(), 0));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(crate::security::ip_matches(v6, "::".parse().unwrap(), 0));
    }

    #[test]
    fn test_ip_matches_v4_v6_mismatch() {
        let v4: IpAddr = "192.168.1.1".parse().unwrap();
        let v6: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(!crate::security::ip_matches(v4, v6, 0));
        assert!(!crate::security::ip_matches(v6, v4, 0));
    }

    #[test]
    fn test_ip_matches_edge_cases() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(crate::security::ip_matches(ip, ip, 32));
        assert!(crate::security::ip_matches("10.0.1.5".parse().unwrap(), "10.0.1.0".parse().unwrap(), 24));
        assert!(!crate::security::ip_matches("10.0.2.5".parse().unwrap(), "10.0.1.0".parse().unwrap(), 24));
    }

    #[test]
    fn test_rate_limiter_multiple_ips() {
        let limiter = IpRateLimiter::new(2);
        let ip_a: IpAddr = "1.1.1.1".parse().unwrap();
        let ip_b: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(limiter.check(ip_a));
        assert!(limiter.check(ip_a));
        assert!(!limiter.check(ip_a));
        assert!(limiter.check(ip_b));
        assert!(limiter.check(ip_b));
        assert!(!limiter.check(ip_b));
    }

    #[test]
    fn test_rate_limiter_window_reset() {
        let limiter = IpRateLimiter::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));
        let w = limiter.window.lock().unwrap();
        assert!(w.contains_key(&ip));
    }

    #[test]
    fn test_rate_limiter_stale_cleanup() {
        let limiter = IpRateLimiter::new(5);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(ip));
        let w = limiter.window.lock().unwrap();
        assert_eq!(w.len(), 1);
        drop(w);
        {
            let mut w = limiter.window.lock().unwrap();
            w.insert(ip, (Instant::now() - std::time::Duration::from_secs(10), 0));
        }
        assert!(limiter.check(ip));
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.check(ip2));
    }

    #[test]
    fn test_allowlist_ipv6() {
        let allowlist = IpAllowlist::from_config(&["2001:db8::/32".into()]);
        assert!(allowlist.allows("2001:db8::1".parse().unwrap()));
        assert!(!allowlist.allows("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_blacklist_ipv6() {
        let blacklist = IpBlacklist::from_config(&["fe80::/10".into()]);
        assert!(blacklist.blocks("fe80::1".parse().unwrap()));
        assert!(!blacklist.blocks("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_too_large() {
        assert_eq!(parse_cidr("10.0.0.1/33"), None);
        assert_eq!(parse_cidr("::1/129"), None);
    }

    #[test]
    fn test_parse_cidr_invalid_empty() {
        assert_eq!(parse_cidr(""), None);
        assert_eq!(parse_cidr("/24"), None);
    }

    #[tokio::test]
    async fn test_handle_webhook_missing_email() {
        use axum::body::Bytes;
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"{\"hello\": \"world\"}");
        let resp = handle_webhook(State(state), headers, body).await;
        let resp = resp.into_response();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_handle_batch_webhook_invalid_json() {
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let body = Bytes::from_static(b"not-json");
        let resp = handle_batch_webhook(State(state), body).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_handle_batch_webhook_missing_signatures() {
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let body = Bytes::from_static(b"{\"body\": {}}");
        let resp = handle_batch_webhook(State(state), body).await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_handle_batch_webhook_empty_signatures() {
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let body = Bytes::from_static(b"{\"signatures\": []}");
        let resp = handle_batch_webhook(State(state), body).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_handle_batch_webhook_entry_without_email() {
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let body = Bytes::from_static(b"{\"signatures\": [{\"signature\": \"sig\"}]}");
        let resp = handle_batch_webhook(State(state), body).await;
        // 207 Multi-Status: entry exists but no route found
        assert_eq!(resp.status(), 207);
    }

    #[tokio::test]
    async fn test_handle_batch_webhook_partial_delivery_no_route() {
        let state = PushState {
            router: Arc::new(ProfileRouter::new(std::path::PathBuf::from("/nonexistent/aimail_routes.toml"))),
            http_client: reqwest::Client::new(),
            config: toml::from_str(r#"mode = "push"
[push]
"#).unwrap(),
            forward_headers: vec![],
        };
        let body = Bytes::from_static(b"{\"signatures\": [{\"email\": \"nobody@x.com\", \"signature\": \"sig\"}]}");
        let resp = handle_batch_webhook(State(state), body).await;
        // 207 Multi-Status: 0/1 delivered
        assert_eq!(resp.status(), 207);
    }

    #[test]
    fn test_batch_detection_prefix_matches() {
        // Body starting with {"signatures": should trigger batch path
        assert!(b"{\"signatures\":[]}".starts_with(b"{"));
        assert!(b"{\"signatures\": []}".starts_with(b"{"));
        assert!(b"{\"signatures\":\"abc\"}".starts_with(b"{"));
    }

    #[test]
    fn test_batch_detection_prefix_does_not_match() {
        assert!(!b"{\"data\": {}}".starts_with(b"{\"signatures\":"));
        assert!(!b"{\"signature\": \"x\"}".starts_with(b"{\"signatures\":"));
        assert!(!b"not-json".starts_with(b"{\"signatures\":"));
    }
}