//! Route table: email → (host, port) lookup, loaded from `aimail_routes.toml`.
//!
//! Routes are registered via the admin API (`POST /api/v1/routes`), which
//! persists to `aimail_routes.toml` and updates in-memory routes immediately.
//!
//! On startup, routes are loaded from the file. A lightweight inotify watcher
//! monitors the routes file for hot-reload on manual edits.
//!
//! Entry format (TOML):
//! ```toml
//! "agent@domain.com" = "127.0.0.1:8645"
//! ".*@domain\\.com" = "192.168.1.2:8645"   # regex pattern
//! ```
//!
//! Lookup priority:
//!   1. Exact email match
//!   2. Regex pattern fallback
//!   3. No match → `None` + warning log

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use notify::{Event, RecursiveMode, Watcher};

/// A single routing entry.
#[derive(Debug, Clone)]
pub struct ProfileRoute {
    pub email: String,
    pub host: String,
    pub port: u16,
    /// Cached target URL — computed once, reused for all lookups.
    /// Either a full URL (registered via API / routes file) or
    /// `http://{host}:{port}/webhooks/aimail-inbound` when only host:port
    /// was given (legacy default path).
    target_url: String,
}

impl ProfileRoute {
    pub fn target_url(&self) -> &str {
        &self.target_url
    }

    /// Build a route from a full URL (scheme://host[:port][/path]).
    /// The path is preserved verbatim — no `/webhooks/aimail-inbound`
    /// suffix is appended, so agent endpoints with custom paths
    /// (e.g. OpenClaw `/hook`) work unchanged.
    fn from_url(email: String, url: &str) -> Self {
        // Parse scheme://host[:port][/path] without pulling in a URL crate.
        let url = url.trim();
        // Preserve the scheme so target_url round-trips https correctly
        // (AUDIT-1 A3: https routes must probe 443, not 80).
        let scheme = if url.starts_with("https://") { "https" } else { "http" };
        let rest = if let Some(s) = url.strip_prefix("http://") { s }
            else if let Some(s) = url.strip_prefix("https://") { s }
            else { url }; // bare host:port/path → treat as http
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        // IPv6 literal [::1]:port or host:port
        let (host, port) = if let Some(b) = authority.strip_prefix('[') {
            match b.split_once("]:") {
                Some((h, p)) => (format!("[{}]", h), p.parse::<u16>().unwrap_or(80)),
                None => (format!("[{}]", b.trim_end_matches(']')), 80),
            }
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(80))
        } else {
            (authority.to_string(), 80)
        };
        let target_url = format!("{}://{}{}", scheme, authority, path);
        Self { email, host, port, target_url }
    }

    fn new(email: String, host: String, port: u16) -> Self {
        let target_url = format!("http://{}:{}/webhooks/aimail-inbound", host, port);
        Self { email, host, port, target_url }
    }
}

/// Thread-safe email → route lookup table.
pub struct ProfileRouter {
    routes: RwLock<HashMap<String, ProfileRoute>>,
    routes_file: PathBuf,
    /// Regex patterns loaded from routes file, kept for lookup-time fallback.
    regex_patterns: RwLock<Vec<(regex::Regex, String, String, u16)>>,
    /// Guard flag to prevent write-back loop when writing routes file.
    writing_routes: AtomicBool,
}

impl ProfileRouter {
    pub fn new(routes_file: PathBuf) -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            routes_file,
            regex_patterns: RwLock::new(Vec::new()),
            writing_routes: AtomicBool::new(false),
        }
    }

    /// Load routes from `aimail_routes.toml` into memory.
    pub fn load_from_file(&self) {
        self.writing_routes.store(false, Ordering::SeqCst);

        let file_overrides = self.load_routes_file();

        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        routes.clear();
        let mut raw_patterns: Vec<(regex::Regex, String, String, u16)> = Vec::new();

        // First pass: insert exact email matches directly
        for (key, route) in &file_overrides {
            if Self::is_regex_pattern(key) {
                continue; // handled in second pass
            }
            routes.insert(key.clone(), route.clone());
            tracing::info!(email = %key, host = %route.host, port = route.port,
                           "Route loaded from file (exact match)");
        }

        // Second pass: regex patterns — expand against all known emails
        let all_emails: Vec<String> = routes.keys().cloned().collect();
        for (key, route) in &file_overrides {
            if !Self::is_regex_pattern(key) {
                continue;
            }
            let re = match regex::Regex::new(key) {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(key = %key, "Invalid regex pattern in routes file — skipping");
                    continue;
                }
            };
            raw_patterns.push((re.clone(), key.clone(), route.host.clone(), route.port));
            for email in &all_emails {
                if re.is_match(email) {
                    // Don't overwrite exact matches with regex expansions
                    if routes.contains_key(email) {
                        continue;
                    }
                    tracing::info!(email = %email, pattern = %key, host = %route.host, port = route.port,
                                   "Regex pattern expanded");
                    routes.insert(email.clone(), route.clone());
                }
            }
        }
        {
            let mut ptns = self.regex_patterns.write().unwrap_or_else(|e| e.into_inner());
            *ptns = raw_patterns;
        }

        let count = routes.len();
        drop(routes);
        tracing::info!(count, "Routes loaded from file");
    }

    /// Parse "host:port" string into (host, port).
    fn parse_addr(s: &str) -> Option<(String, u16)> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        if let Some(rest) = s.strip_prefix('[') {
            let (addr, port_str) = rest.split_once("]:")?;
            let port: u16 = port_str.parse().ok()?;
            return Some((format!("[{}]", addr), port));
        }

        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }

        if let Ok(port) = s.parse::<u16>() {
            return Some(("127.0.0.1".to_string(), port));
        }

        Some((s.to_string(), 8645))
    }

    /// Load route entries from ~/.hermes/aimail_routes.toml.
    fn load_routes_file(&self) -> HashMap<String, ProfileRoute> {
        let path = &self.routes_file;
        let Ok(file_content) = std::fs::read_to_string(path) else { return HashMap::new() };

        let parsed: HashMap<String, String> = match toml::from_str(&file_content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse routes file — skipping");
                return HashMap::new();
            }
        };

        let mut overrides = HashMap::new();
        for (key, value) in parsed {
            let value = value.trim();
            // Full URL (with path) → use verbatim; bare host:port → legacy default path
            let route = if value.contains('/') || value.contains("://") {
                ProfileRoute::from_url(key.clone(), value)
            } else {
                match Self::parse_addr(value) {
                    Some((host, port)) => ProfileRoute::new(key.clone(), host, port),
                    None => {
                        tracing::warn!(key = %key, value = %value, "Invalid 'host:port' in routes file — skipping");
                        continue;
                    }
                }
            };
            overrides.insert(key.clone(), route);
        }

        overrides
    }

    fn is_regex_pattern(key: &str) -> bool {
        key.contains(|c: char| matches!(c, '*' | '+' | '?' | '[' | ']' | '(' | ')' | '^' | '$' | '|' | '\\'))
    }

    /// Look up the route for a given agent email address.
    pub fn lookup(&self, email: &str) -> Option<ProfileRoute> {
        let routes = self.routes.read().unwrap_or_else(|e| e.into_inner());

        if let Some(route) = routes.get(email) {
            return Some(route.clone());
        }
        drop(routes);

        let pattern_match: Option<(String, String, u16)> = {
            let patterns = self.regex_patterns.read().unwrap_or_else(|e| e.into_inner());
            patterns.iter().find(|(re, _, _, _)| re.is_match(email))
                .map(|(_, k, h, p)| (k.clone(), h.clone(), *p))
        };

        if let Some((ref _key, ref host, port)) = pattern_match {
            tracing::info!(email = %email, host = %host, port = port, "Regex pattern matched on lookup");
            let route = ProfileRoute::new(email.to_string(), host.clone(), port);
            let mut w = self.routes.write().unwrap_or_else(|e| e.into_inner());
            w.insert(email.to_string(), route.clone());
            return Some(route);
        }

        tracing::warn!(email = %email, "No route found");
        None
    }

    /// Add or update a route for an exact email, then persist to file.
    /// `host_or_url` accepts either a full URL (`http://host:port/path`,
    /// path preserved verbatim) or a bare `host:port` (legacy default
    /// `/webhooks/aimail-inbound` path).
    pub fn update_route(&self, email: &str, host_or_url: &str, port: u16) {
        let route = if host_or_url.contains('/') || host_or_url.contains("://") {
            ProfileRoute::from_url(email.into(), host_or_url)
        } else {
            ProfileRoute::new(email.into(), host_or_url.into(), port)
        };
        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        routes.insert(email.into(), route);
        drop(routes);
        self.write_current_routes();
    }

    /// Remove a route by exact email, then persist to file.
    pub fn remove_route(&self, email: &str) {
        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        routes.remove(email);
        drop(routes);
        self.write_current_routes();
    }

    /// Return all current routes.
    pub fn list_routes(&self) -> Vec<ProfileRoute> {
        self.routes.read().unwrap_or_else(|e| e.into_inner())
            .values().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn route_count(&self) -> usize {
        self.routes.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Return all known agent emails (for pull-mode email filtering).
    pub fn list_emails(&self) -> Vec<String> {
        self.routes.read().unwrap_or_else(|e| e.into_inner())
            .keys().cloned().collect()
    }

    /// Write current in-memory routes directly to aimail_routes.toml.
    /// Avoids read-modify-write race by not re-reading the file.
    fn write_current_routes(&self) {
        let path = &self.routes_file;
        self.writing_routes.store(true, Ordering::SeqCst);
        let routes = self.routes.read().unwrap_or_else(|e| e.into_inner());
        let mut out = String::from(
            "# Auto-generated by aimail-bridge.\n\
             # File changes take effect immediately.\n"
        );
        let mut keys: Vec<&String> = routes.keys().collect();
        keys.sort();
        for email in keys {
            if let Some(route) = routes.get(email) {
                // Persist the full target URL when it carries a custom path
                // (not the legacy /webhooks/aimail-inbound default), so
                // restarts keep exact endpoint paths.
                let value = if route.target_url.ends_with("/webhooks/aimail-inbound")
                    && route.target_url.starts_with(&format!("http://{}:{}", route.host, route.port))
                {
                    format!("{}:{}", route.host, route.port)
                } else {
                    route.target_url.clone()
                };
                out.push_str(&format!("\"{}\" = \"{}\"\n", email, value));
            }
        }
        if let Err(e) = std::fs::write(path, &out) {
            tracing::warn!(path = %path.display(), error = %e, "Failed to write routes file");
        }
        // Reset the guard AFTER the write completes so the file watcher can
        // pick up external edits again. A self-triggered reload right after
        // our own write is harmless (idempotent reload of identical content);
        // the real bug was NEVER resetting — external edits stopped
        // hot-reloading entirely (AUDIT-1 A1).
        self.writing_routes.store(false, Ordering::SeqCst);
    }
}

/// Start a lightweight inotify watcher that monitors `aimail_routes.toml`.
/// On file changes (not written by us), reloads routes from the file.
pub fn start_routes_watcher(router: Arc<ProfileRouter>) -> notify::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?;

    let routes_path = router.routes_file.clone();
    if routes_path.exists() {
        watcher.watch(&routes_path, RecursiveMode::NonRecursive)?;
    }

    tokio::spawn(async move {
        let _watcher = watcher;
        while let Ok(event) = rx.recv() {
            let is_our_write = router.writing_routes.load(Ordering::SeqCst);
            let is_routes_file = event.paths.iter().any(|p| *p == routes_path);
            if is_routes_file && !is_our_write {
                tracing::debug!("Routes file changed — reloading");
                router.load_from_file();
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write_routes_file(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    // ── parse_addr ──────────────────────────────────────

    #[test]
    fn test_parse_addr_ipv4_with_port() {
        let (host, port) = ProfileRouter::parse_addr("192.168.1.2:8645").unwrap();
        assert_eq!(host, "192.168.1.2");
        assert_eq!(port, 8645);
    }

    #[test]
    fn test_parse_addr_ipv6_with_port() {
        let (host, port) = ProfileRouter::parse_addr("[::1]:8645").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8645);
    }

    #[test]
    fn test_parse_addr_bare_port() {
        let (host, port) = ProfileRouter::parse_addr("8645").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8645);
    }

    #[test]
    fn test_parse_addr_bare_hostname() {
        let (host, port) = ProfileRouter::parse_addr("myhost.local").unwrap();
        assert_eq!(host, "myhost.local");
        assert_eq!(port, 8645);
    }

    #[test]
    fn test_parse_addr_empty() {
        assert!(ProfileRouter::parse_addr("").is_none());
    }

    #[test]
    fn test_parse_addr_hostname_with_port() {
        let (host, port) = ProfileRouter::parse_addr("bridge.example.com:38080").unwrap();
        assert_eq!(host, "bridge.example.com");
        assert_eq!(port, 38080);
    }

    // ── load_from_file ──────────────────────────────────

    #[test]
    fn test_load_from_file_and_lookup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        write_routes_file(&routes_file, r#""a1@t.local" = "127.0.0.1:8001""#);
        let router = ProfileRouter::new(routes_file.clone());
        router.load_from_file();
        assert_eq!(router.route_count(), 1);
        assert!(router.lookup("a1@t.local").is_some());
        assert!(router.lookup("nobody@t.local").is_none());
    }

    #[test]
    fn test_load_from_file_overrides_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        let router = ProfileRouter::new(routes_file);
        router.load_from_file();
        assert_eq!(router.route_count(), 0);
    }

    #[test]
    fn test_routes_file_regex_pattern_matches() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        write_routes_file(&routes_file, r#""a1@admin.relay" = "127.0.0.1:8765"
".*@admin" = "10.0.0.88:8765"
"#);
        let router = ProfileRouter::new(routes_file);
        router.load_from_file();
        let route = router.lookup("a1@admin.relay").unwrap();
        assert_eq!(route.host, "127.0.0.1", "Exact match wins over regex");
        assert_eq!(route.port, 8765);
    }

    #[test]
    fn test_route_added_via_api_persists() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        let router = ProfileRouter::new(routes_file.clone());
        router.update_route("alice@x.com", "127.0.0.1", 8645);
        // Verify routes file written
        let content = std::fs::read_to_string(&routes_file).unwrap();
        assert!(content.contains("alice@x.com"));
        assert!(content.contains("127.0.0.1:8645"));
    }

    #[test]
    fn test_route_from_full_url_preserves_path() {
        let route = ProfileRoute::from_url(
            "alice@x.com".into(),
            "http://127.0.0.1:8799/hook",
        );
        assert_eq!(route.target_url(), "http://127.0.0.1:8799/hook");
        assert_eq!(route.host, "127.0.0.1");
        assert_eq!(route.port, 8799);
    }

    #[test]
    fn test_route_from_full_url_no_port() {
        let route = ProfileRoute::from_url(
            "bob@x.com".into(),
            "http://10.0.0.5/webhooks/agentmail-inbound",
        );
        assert_eq!(route.target_url(), "http://10.0.0.5/webhooks/agentmail-inbound");
        assert_eq!(route.host, "10.0.0.5");
        assert_eq!(route.port, 80);
    }

    #[test]
    fn test_load_full_url_routes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        write_routes_file(&routes_file,
            "\"a1@t.local\" = \"http://127.0.0.1:8799/hook\"\n\"a2@t.local\" = \"127.0.0.1:8002\"\n");
        let router = ProfileRouter::new(routes_file.clone());
        router.load_from_file();
        let r1 = router.lookup("a1@t.local").unwrap();
        assert_eq!(r1.target_url(), "http://127.0.0.1:8799/hook", "full URL path preserved");
        let r2 = router.lookup("a2@t.local").unwrap();
        assert_eq!(r2.target_url(), "http://127.0.0.1:8002/webhooks/aimail-inbound",
            "bare host:port falls back to legacy path");
    }

    #[test]
    fn test_route_api_persists_full_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        let routes_file = tmp.path().join("aimail_routes.toml");
        let router = ProfileRouter::new(routes_file.clone());
        router.update_route("c1@t.local", "http://127.0.0.1:8799/hook", 0);
        let content = std::fs::read_to_string(&routes_file).unwrap();
        assert!(content.contains("\"http://127.0.0.1:8799/hook\""), "full URL persisted: {}", content);
        let r = router.lookup("c1@t.local").unwrap();
        assert_eq!(r.target_url(), "http://127.0.0.1:8799/hook");
    }
}
