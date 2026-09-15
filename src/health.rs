//! Route health checker — periodic TCP probe of webhook targets.
//!
//! Runs alongside the pull loop (or push server). Every N seconds, iterates
//! over all unique route targets in the route table and attempts a TCP
//! connection. Targets that fail consecutively beyond a threshold are
//! considered dead and all routes pointing to them are removed.
//!
//! This auto-cleans stale routes when:
//! - A Hermes gateway moves to a different port
//! - A profile is deleted without unregistering its route
//! - A remote agent gateway goes permanently offline

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;

use crate::config::HealthConfig;
use crate::router::ProfileRouter;

/// Start the route health check loop. Runs until shutdown is signalled.
pub async fn start_route_health(
    router: Arc<ProfileRouter>,
    config: HealthConfig,
    shutdown: Arc<AtomicBool>,
) {
    let mut failures: HashMap<String, u32> = HashMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(config.check_interval_sec));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    tracing::info!(
        interval_sec = config.check_interval_sec,
        fail_threshold = config.fail_threshold,
        connect_timeout_sec = config.connect_timeout_sec,
        "Route health check started"
    );

    loop {
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("Route health check shutting down");
            return;
        }
        interval.tick().await;
        check_routes(&router, &mut failures, &config).await;
    }
}

/// One round of route health checks.
async fn check_routes(router: &ProfileRouter, failures: &mut HashMap<String, u32>, config: &HealthConfig) {
    let routes = router.list_routes();
    if routes.is_empty() {
        return;
    }

    // Group by unique target — parse host:port from the route's target URL
    // (handles https URLs where r.port defaults to 80 but the real endpoint
    // is 443; AUDIT-1 A3).
    let mut target_groups: HashMap<String, Vec<String>> = HashMap::new();
    for r in &routes {
        let target = route_target_key(r);
        target_groups.entry(target).or_default().push(r.email.clone());
    }

    let mut dead_targets: Vec<String> = Vec::new();

    for (target, emails) in &target_groups {
        let (host, port_str) = match target.split_once(':') {
            Some((h, p)) => (h, p),
            None => continue,
        };
        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let ok = probe_target(host, port, config.connect_timeout_sec).await;

        if ok {
            failures.remove(target);
            continue;
        }

        // Increment failure counter
        let count = failures.entry(target.clone()).or_insert(0);
        *count += 1;

        if *count >= config.fail_threshold {
            tracing::warn!(
                target = %target,
                emails = ?emails,
                consecutive_failures = *count,
                "Route target unreachable — removing {} route(s)",
                emails.len(),
            );
            dead_targets.push(target.clone());
        } else {
            tracing::debug!(
                target = %target,
                failures = *count,
                threshold = config.fail_threshold,
                "Route target probe failed (will retry)"
            );
        }
    }

    // Remove dead targets
    for target in &dead_targets {
        if let Some(emails) = target_groups.get(target) {
            for email in emails {
                router.remove_route(email);
            }
        }
        failures.remove(target);
    }

    if !dead_targets.is_empty() {
        let remaining = router.route_count();
        tracing::info!(
            removed = dead_targets.len(),
            remaining_routes = remaining,
            "Stale routes cleaned up"
        );
    }
}

/// Extract "host:port" from a route's target URL — handles https URLs
/// (port 443 when absent) and full paths (AUDIT-1 A3).
fn route_target_key(r: &crate::router::ProfileRoute) -> String {
    let url = r.target_url();
    // Strip scheme
    let rest = url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // Split authority from path
    let (authority, _) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Parse host + port (IPv6 [::1]:port supported)
    if let Some(b) = authority.strip_prefix('[') {
        if let Some((h, p)) = b.split_once("]:") {
            if let Ok(port) = p.parse::<u16>() {
                return format!("[{}]:{}", h, port);
            }
        }
        return format!("[{}]:443", b.trim_end_matches(']'));
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return format!("{}:{}", h, port);
        }
    }
    let port = if url.starts_with("https://") { 443 } else { 80 };
    format!("{}:{}", authority, port)
}

/// TCP probe: connect to host:port with timeout.
async fn probe_target(host: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::debug!(target = %addr, error = %e, "TCP probe failed");
            false
        }
        Err(_) => {
            tracing::debug!(target = %addr, "TCP probe timed out");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router_with_route(target: &str) -> ProfileRouter {
        let router = ProfileRouter::new(std::path::PathBuf::from("/nonexistent/routes.toml"));
        router.update_route("a@x.com", target, 0);
        router
    }

    #[test]
    fn test_route_target_key_http_url() {
        let router = router_with_route("http://127.0.0.1:8646/webhooks/agentmail-inbound");
        let r = router.list_routes().pop().unwrap();
        assert_eq!(route_target_key(&r), "127.0.0.1:8646");
    }

    #[test]
    fn test_route_target_key_https_url_no_port() {
        let router = router_with_route("https://10.0.0.5/webhooks/agentmail-inbound");
        let r = router.list_routes().pop().unwrap();
        // https without port → 443 (AUDIT-1 A3: r.port would be 80)
        assert_eq!(route_target_key(&r), "10.0.0.5:443");
    }

    #[test]
    fn test_route_target_key_http_url_no_port() {
        let router = router_with_route("http://10.0.0.6/hook");
        let r = router.list_routes().pop().unwrap();
        assert_eq!(route_target_key(&r), "10.0.0.6:80");
    }

    #[test]
    fn test_route_target_key_ipv6() {
        let router = router_with_route("http://[::1]:8799/hook");
        let r = router.list_routes().pop().unwrap();
        assert_eq!(route_target_key(&r), "[::1]:8799");
    }

    #[test]
    fn test_route_target_key_bare_hostport() {
        // Legacy bare host:port route → target_url has /webhooks/aimail-inbound
        let router = ProfileRouter::new(std::path::PathBuf::from("/nonexistent/routes.toml"));
        router.update_route("e@x.com", "127.0.0.1", 8645);
        let r = router.list_routes().pop().unwrap();
        assert_eq!(route_target_key(&r), "127.0.0.1:8645");
    }
}
