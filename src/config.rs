//! Bridge configuration: `aimail_bridge.toml` + env var overrides.
//! Config format aligned with aimail-gateway.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Full bridge configuration, deserialised from `aimail_bridge.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct BridgeConfig {
    #[serde(default = "default_mode")]
    pub mode: String, // "push" | "pull"

    /// Listen address in "host:port" format (e.g. "0.0.0.0:38080").
    /// Used for admin API (/health, /api/v1/routes) and push webhooks.
    /// `bind` is the canonical name (aligned with aimail-gateway/advanced);
    /// legacy `addr` key still parses via serde alias.
    #[serde(default = "default_listen_bind", alias = "addr")]
    pub bind: String,

    /// Public hostname or IP:port announced to gateway (promoted from push.hostname).
    /// - domain:port → TLS enabled (ACME or static cert)
    /// - ip:port     → plain HTTP, no TLS
    #[serde(default)]
    pub hostname: Option<String>,

    /// Optional static TLS certificate path (PEM format, domain hostname only).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    /// Optional static TLS private key path (PEM format, domain hostname only).
    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// ACME certificate cache directory. Defaults to ~/.acme_cache/
    /// (used when hostname is a domain and no static tls_cert/tls_key).
    #[serde(default)]
    pub acme_cache: Option<PathBuf>,

    /// Contact email for ACME account registration (optional; Let's Encrypt
    /// uses it for expiry notices). When unset, a placeholder is used.
    #[serde(default)]
    pub acme_email: Option<String>,

    /// Directory where ACME HTTP-01 challenge proofs are written for an
    /// external HTTP server (nginx/caddy on port 80). When unset, the
    /// bridge starts a temporary listener on port 80 itself.
    #[serde(default)]
    pub acme_challenge_path: Option<PathBuf>,

    /// Allowed source IPs/CIDRs for admin API access.
    /// Requests to /health and /api/v1/* from other IPs get 403.
    /// Default: localhost only (AUDIT-1 D1 — empty previously meant
    /// allow-all, a route-poisoning risk on public deployments).
    #[serde(default = "default_admin_allowed_ips")]
    pub admin_allowed_ips: Vec<String>,

    /// Forward headers that bridge passes through to gateway.
    /// Single mode: whitelist filter (only these headers are forwarded).
    /// Batch mode: per-recipient headers built from entry fields.
    /// Default: standard AIMail relay headers.
    #[serde(default = "default_forward_headers")]
    pub forward_headers: Vec<String>,

    #[serde(default)]
    pub push: PushConfig,

    #[serde(default)]
    pub pull: PullConfig,

    /// Where to find Hermes profiles (default: ~/.hermes/profiles).
    #[serde(default)]
    pub hermes_home: Option<PathBuf>,

    /// Path to the Hermes default profile (~/.hermes/). Computed at startup.
    #[serde(skip)]
    pub default_profile_dir: PathBuf,

    /// Path to aimail_routes.toml (default: alongside aimail_bridge.toml).
    #[serde(skip)]
    pub routes_file: PathBuf,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Route health check configuration.
    #[serde(default)]
    pub health: HealthConfig,
}

impl BridgeConfig {
    /// Parse `bind` into (host, port). Default port: 80.
    pub fn parsed_bind(&self) -> (&str, u16) {
        if let Some((host, port_str)) = self.bind.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host, port);
            }
        }
        (&self.bind, 80)
    }

    /// Returns true if TLS should be enabled (hostname is a domain, not IP).
    /// Used by main.rs TLS branch (static certs OR ACME when domain).
    pub fn has_tls(&self) -> bool {
        self.hostname.as_ref().map_or(false, |h| !is_ip_address(h))
    }

    /// True when dual-port mode (80 → 443 redirect) is active.
    /// Conditions: bind port == 80 AND hostname is a domain (not IP).
    pub fn is_dual_port(&self) -> bool {
        let (_, port) = self.parsed_bind();
        port == 80 && self.hostname.as_ref().map_or(false, |h| !is_ip_address(h))
    }
}

/// Check if a hostname string is an IP address (with optional port suffix).
pub(crate) fn is_ip_address(host: &str) -> bool {
    let host_only = host.split(':').next().unwrap_or(host);
    host_only.parse::<std::net::IpAddr>().is_ok()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushConfig {
    /// IP/CIDR allowlist for webhook POSTs. Empty = allow all.
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// IP/CIDR blacklist for webhook POSTs. Empty = none.
    #[serde(default)]
    pub blacklist_ips: Vec<String>,

    /// Rate limit (requests/sec per source IP). 0 = disabled. Default 30.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// Max request body size in MB. Default 20.
    #[serde(default = "default_body_limit")]
    pub body_limit_mb: u32,

    /// Virtual host sites (optional).
    #[serde(default)]
    pub sites: Vec<VhostSiteConfig>,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            blacklist_ips: Vec::new(),
            rate_limit: 30,
            body_limit_mb: 20,
            sites: Vec::new(),
        }
    }
}

fn default_rate_limit() -> u32 { 30 }
fn default_body_limit() -> u32 { 20 }

fn default_forward_headers() -> Vec<String> {
    // 只转发 AIMail 业务头; 单投模式只复制"在场"的头, 不会产生重复。
    vec![
        "X-AIMail-Email".into(),
        "X-AIMail-Timestamp".into(),
        "X-Mailrelay-Timestamp".into(), // 中转协议兼容名
        "X-Webhook-Signature".into(),
        "content-type".into(),
    ]
}

/// TOML-deserialized virtual host site configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VhostSiteConfig {
    pub domain: String,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub redirect: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullConfig {
    #[serde(default)]
    pub aimail_url: String,
    #[serde(default)]
    pub admin_key: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_sec: u64,
    #[serde(default)]
    pub system_id: String,

    /// Optional multi-system pull configuration. Each entry pulls its own
    /// system's pending deliveries (per-system API key / system_id).
    /// When empty, a single system is synthesized from the flat fields above
    /// (backward compatible with the legacy single-system config).
    #[serde(default)]
    pub systems: Vec<PullSystemConfig>,
}

/// One pull target (a single cloud system).
#[derive(Debug, Clone, Deserialize)]
pub struct PullSystemConfig {
    #[serde(default)]
    pub aimail_url: String,
    #[serde(default)]
    pub admin_key: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_sec: u64,
    #[serde(default)]
    pub system_id: String,
}

impl PullSystemConfig {
    /// Returns the effective API key: prefer api_key, fall back to admin_key.
    pub fn effective_key(&self) -> &str {
        if !self.api_key.is_empty() { &self.api_key } else { &self.admin_key }
    }
}

impl PullConfig {
    /// Returns the effective API key: prefer api_key, fall back to admin_key.
    /// Kept for compatibility; new code should use PullSystemConfig::effective_key.
    #[allow(dead_code)]
    pub fn effective_key(&self) -> &str {
        if !self.api_key.is_empty() { &self.api_key } else { &self.admin_key }
    }

    /// Resolve the list of pull systems: explicit `systems` array when
    /// non-empty, otherwise a single synthesized entry from the flat fields
    /// (legacy single-system config compatibility).
    pub fn resolved_systems(&self) -> Vec<PullSystemConfig> {
        if !self.systems.is_empty() {
            return self.systems.clone();
        }
        vec![PullSystemConfig {
            aimail_url: self.aimail_url.clone(),
            admin_key: self.admin_key.clone(),
            api_key: self.api_key.clone(),
            poll_interval_sec: self.poll_interval_sec,
            system_id: self.system_id.clone(),
        }]
    }
}

/// Logging configuration (aimail-gateway compatible).
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: Some(PathBuf::from("/var/log/aimail-bridge.log")),
        }
    }
}

/// Route health check configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    /// How often to probe each route target (seconds).
    #[serde(default = "default_health_check_interval")]
    pub check_interval_sec: u64,
    /// Consecutive failures before removing routes to a dead target.
    #[serde(default = "default_health_fail_threshold")]
    pub fail_threshold: u32,
    /// TCP connection timeout per probe (seconds).
    #[serde(default = "default_health_connect_timeout")]
    pub connect_timeout_sec: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_sec: 60,
            fail_threshold: 3,
            connect_timeout_sec: 3,
        }
    }
}

// Default helpers
fn default_mode() -> String { "push".into() }
fn default_listen_bind() -> String { "0.0.0.0:38080".into() }
fn default_poll_interval() -> u64 { 10 }
fn default_log_level() -> String { "info".into() }
fn default_health_check_interval() -> u64 { 60 }
fn default_health_fail_threshold() -> u32 { 3 }
fn default_health_connect_timeout() -> u64 { 3 }
/// Admin API default: localhost only (AUDIT-1 D1). Empty previously
/// meant allow-all — route management exposed to any IP on public
/// deployments is a poisoning vector.
fn default_admin_allowed_ips() -> Vec<String> {
    vec!["127.0.0.1".into(), "::1".into()]
}

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            aimail_url: String::new(),
            admin_key: String::new(),
            api_key: String::new(),
            poll_interval_sec: 10,
            system_id: String::new(),
            systems: Vec::new(),
        }
    }
}

impl BridgeConfig {
    /// Load config from a TOML file, then apply environment variable overrides.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join("aimail_bridge.toml"));
        let mut cfg: BridgeConfig = {
            let content = std::fs::read_to_string(&config_path)?;
            toml::from_str(&content)?
        };

        // Env overrides
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_MODE") { cfg.mode = v; }
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_HOSTNAME") {
            if !v.is_empty() { cfg.hostname = Some(v); }
        }
        if let Ok(v) = std::env::var("AIMAIL_GATEWAY_URL") { cfg.pull.aimail_url = v; }
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_ADMIN_KEY") { cfg.pull.admin_key = v; }
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_SYSTEM_ID") { cfg.pull.system_id = v; }
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_POLL_SECS") {
            cfg.pull.poll_interval_sec = v.parse().unwrap_or(10);
        }
        if let Ok(v) = std::env::var("AIMAIL_BRIDGE_ALLOWED_IPS") {
            cfg.push.allowed_ips = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(v) = std::env::var("HERMES_HOME") {
            cfg.hermes_home = Some(PathBuf::from(v));
        }

        // Default profile dir
        let hermes_root = cfg.hermes_home.clone().unwrap_or_else(|| {
            dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp")).join(".hermes")
        });
        cfg.default_profile_dir = hermes_root;
        cfg.routes_file = config_path.parent().unwrap_or(Path::new(".")).join("aimail_routes.toml");

        // Normalize aimail_url: add http:// if no scheme present
        if !cfg.pull.aimail_url.contains("://") && !cfg.pull.aimail_url.is_empty() {
            cfg.pull.aimail_url = format!("http://{}", cfg.pull.aimail_url);
        }
        // Same normalization for each entry of the multi-system array —
        // otherwise reqwest gets a URL without scheme and the pull loop
        // dies with "builder error" (AUDIT-2 / e2e M-Q caught this).
        for sys in &mut cfg.pull.systems {
            if !sys.aimail_url.contains("://") && !sys.aimail_url.is_empty() {
                sys.aimail_url = format!("http://{}", sys.aimail_url);
            }
        }

        Ok(cfg)
    }

    /// Validate configuration and emit warnings for insecure settings.
    pub fn validate(&self) {
        if self.mode == "pull" {
            for (i, sys) in self.pull.resolved_systems().iter().enumerate() {
                if sys.aimail_url.is_empty() {
                    tracing::warn!(system_index = i, "pull.systems[{}].aimail_url is empty — pull loop will fail", i);
                }
                if sys.admin_key.is_empty() && sys.api_key.is_empty() {
                    tracing::warn!(system_index = i, "pull.systems[{}] has no admin_key/api_key — authentication will fail", i);
                }
                if sys.system_id.is_empty() {
                    tracing::warn!(system_index = i, "pull.systems[{}].system_id is empty — pending query will fail", i);
                }
            }
        }
        if self.hostname.is_some() && self.tls_cert.is_none() && self.tls_key.is_none() {
            tracing::info!("hostname is set — will attempt ACME auto-certificate");
        }
        if self.is_dual_port() {
            tracing::info!("dual-port mode enabled (port 80 → 443)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
aimail_url = "http://x"
admin_key = "k"
system_id = "s"
"#).unwrap();
        assert_eq!(cfg.mode, "pull");
        assert_eq!(cfg.bind, "0.0.0.0:38080");
        assert_eq!(cfg.admin_allowed_ips, vec!["127.0.0.1", "::1"], "D1: admin API defaults to localhost-only");
        assert_eq!(cfg.push.body_limit_mb, 20);
        assert_eq!(cfg.push.rate_limit, 30);
        assert!(cfg.hostname.is_none());
    }

    #[test]
    fn test_legacy_addr_alias() {
        // Pre-0.6.2 configs used `addr`; serde alias keeps them working.
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
addr = "127.0.0.1:8080"
"#).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:8080", "legacy addr key maps to bind");
    }

    #[test]
    fn test_bind_with_port() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
bind = "127.0.0.1:8080"
"#).unwrap();
        let (host, port) = cfg.parsed_bind();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_bind_default_port() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
bind = "0.0.0.0"
"#).unwrap();
        let (host, port) = cfg.parsed_bind();
        assert_eq!(host, "0.0.0.0");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_dual_port_detection() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
bind = "0.0.0.0:80"
hostname = "example.com"
"#).unwrap();
        assert!(cfg.is_dual_port());
    }

    #[test]
    fn test_push_config_with_limits() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
bind = "0.0.0.0:8080"
admin_allowed_ips = ["10.0.0.0/8"]
hostname = "bridge.example.com"
[push]
blacklist_ips = ["1.2.3.4"]
allowed_ips = ["10.0.0.0/8"]
rate_limit = 100
body_limit_mb = 50
"#).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:8080");
        assert_eq!(cfg.admin_allowed_ips, vec!["10.0.0.0/8"]);
        assert_eq!(cfg.push.rate_limit, 100);
        assert_eq!(cfg.push.body_limit_mb, 50);
        assert_eq!(cfg.hostname, Some("bridge.example.com".into()));
        assert!(cfg.has_tls());
        assert!(!cfg.is_dual_port()); // port is 8080, not 80
    }

    #[test]
    fn test_no_tls_without_hostname() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
"#).unwrap();
        assert!(!cfg.has_tls());
    }

    #[test]
    fn test_vhost_sites_parse() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "push"
[push]
[[push.sites]]
domain = "www.example.com"
root = "/var/www"
[[push.sites]]
domain = "old.example.com"
redirect = "https://www.example.com"
"#).unwrap();
        assert_eq!(cfg.push.sites.len(), 2);
        assert_eq!(cfg.push.sites[0].domain, "www.example.com");
        assert_eq!(cfg.push.sites[0].root.as_deref(), Some("/var/www"));
        assert_eq!(cfg.push.sites[1].redirect.as_deref(), Some("https://www.example.com"));
    }

    #[test]
    fn test_validate_pull_empty_warns() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
aimail_url = ""
admin_key = ""
system_id = ""
"#).unwrap();
        assert!(cfg.pull.aimail_url.is_empty());
        assert!(cfg.pull.admin_key.is_empty());
        assert!(cfg.pull.system_id.is_empty());
    }

    #[test]
    fn test_admin_allowed_ips_default_localhost() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
aimail_url = "http://x"
admin_key = "k"
system_id = "s"
"#).unwrap();
        assert_eq!(cfg.admin_allowed_ips, vec!["127.0.0.1", "::1"],
                   "D1: admin API defaults to localhost-only");
    }

    #[test]
    fn test_pull_multi_system_resolved() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
systems = [
    { aimail_url = "https://a.tm", admin_key = "ka", system_id = "sys-a", poll_interval_sec = 2 },
    { aimail_url = "https://b.tm", admin_key = "kb", system_id = "sys-b", poll_interval_sec = 5 },
]
"#).unwrap();
        let systems = cfg.pull.resolved_systems();
        assert_eq!(systems.len(), 2);
        assert_eq!(systems[0].system_id, "sys-a");
        assert_eq!(systems[0].effective_key(), "ka");
        assert_eq!(systems[1].poll_interval_sec, 5);
        assert_eq!(systems[1].effective_key(), "kb");
    }

    #[test]
    fn test_pull_multi_system_url_normalized() {
        // systems[] entries without scheme must get http:// (e2e M-Q caught
        // "builder error" when they didn't — flat aimail_url was normalized
        // but the array entries were not).
        let path = std::env::temp_dir().join("aimail_bridge_norm_test.toml");
        std::fs::write(&path, r#"
mode = "pull"
[pull]
systems = [
  { aimail_url = "127.0.0.1:39011", admin_key = "ka", system_id = "sys-a" },
  { aimail_url = "https://b.tm", admin_key = "kb", system_id = "sys-b" },
]
"#).unwrap();
        let cfg = BridgeConfig::load(Some(&path)).unwrap();
        std::fs::remove_file(&path).ok();
        let systems = cfg.pull.resolved_systems();
        assert_eq!(systems[0].aimail_url, "http://127.0.0.1:39011",
                   "scheme-less entry gets http:// prefix");
        assert_eq!(systems[1].aimail_url, "https://b.tm",
                   "entry with explicit scheme untouched");
    }

    #[test]
    fn test_pull_legacy_single_system_resolved() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
aimail_url = "https://a.tm"
admin_key = "legacy-key"
system_id = "legacy-sys"
"#).unwrap();
        assert!(cfg.pull.systems.is_empty(), "no explicit systems array");
        let systems = cfg.pull.resolved_systems();
        assert_eq!(systems.len(), 1, "legacy flat fields synthesize one system");
        assert_eq!(systems[0].system_id, "legacy-sys");
        assert_eq!(systems[0].effective_key(), "legacy-key");
        assert_eq!(systems[0].aimail_url, "https://a.tm");
    }

    #[test]
    fn test_pull_multi_system_api_key_preferred() {
        let cfg: BridgeConfig = toml::from_str(r#"
mode = "pull"
[pull]
systems = [
    { aimail_url = "https://a.tm", admin_key = "ka", api_key = "ak", system_id = "sys-a" },
]
"#).unwrap();
        let systems = cfg.pull.resolved_systems();
        assert_eq!(systems[0].effective_key(), "ak", "api_key preferred over admin_key");
    }
}
