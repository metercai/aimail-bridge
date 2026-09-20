//! aimail-bridge — transparent bridge between the AIMail gateway and local agent systems.
//!
//! Two modes:
//! - **push**: expose a single external endpoint, transparently proxy to gateway webhook ports.
//! - **pull**: outbound long-poll relay's /pending endpoint, forward to gateway, ACK on success.
//!
//! ## CLI
//!
//! ```text
//! aimail-bridge [--daemon] [--pid-file <path>] [--log-file <path>] [--config <path>]
//! ```
//!
//! `--daemon` detaches from the terminal (double-fork), redirects stdio to
//! the log file (default: ~/.hermes/aimail-bridge.log), and writes a PID file
//! (default: ~/.hermes/aimail-bridge.pid).

mod acme;
mod admin;
mod config;
mod health;
mod pull;
mod push;
mod router;
mod security;
mod vhost;

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::config::BridgeConfig;

mod lifecycle;

/// CLI args parsed before daemonize (no async / tokio dependency).
#[derive(Default)]
pub struct CliArgs {
    pub daemon: bool,
    pub pid_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    // 一次性生命周期操作（P1-α：status/stop/check-config，不进 tokio、不 daemonize）
    pub status: bool,
    pub stop: bool,
    pub check_config: bool,
    pub json: bool,
}

pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut cli = CliArgs::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--daemon" | "-d" => cli.daemon = true,
            "--pid-file" => {
                i += 1;
                cli.pid_file = Some(PathBuf::from(&args[i]));
            }
            "--log-file" => {
                i += 1;
                cli.log_file = Some(PathBuf::from(&args[i]));
            }
            "--config" | "-c" => {
                i += 1;
                cli.config_path = Some(PathBuf::from(&args[i]));
            }
            "--status" => cli.status = true,
            "--stop" => cli.stop = true,
            "--check-config" => cli.check_config = true,
            "--json" => cli.json = true,
            "--help" | "-h" => {
                println!("aimail-bridge — transparent relay-gateway bridge\n");
                println!("Usage: aimail-bridge [OPTIONS]\n");
                println!("Options:");
                println!("  -d, --daemon       Detach from terminal, run in background");
                println!(
                    "  --pid-file <path>  PID file path (default: ~/.aimail/bridge/bridge.pid)"
                );
                println!(
                    "  --log-file <path>  Log file path (default: ~/.aimail/bridge/bridge.log)"
                );
                println!("  -c, --config <path> Config file path (default: ./aimail_bridge.toml)");
                println!("  --status           Report whether the bridge is running (read-only)");
                println!(
                    "  --stop             Gracefully stop a running bridge (refuses foreign PIDs)"
                );
                println!("  --check-config     Validate the config only, do not start");
                println!("  --json             Machine-readable output for the above");
                println!("  -h, --help         Show this help\n");
                println!(
                    "Exit codes: 0 ok/running · 1 error/refused · 2 bad config · 3 not running"
                );
                process::exit(0);
            }
            other => {
                eprintln!("Unknown flag: {}\nUse --help for usage.", other);
                process::exit(1);
            }
        }
        i += 1;
    }
    cli
}

/// Double-fork daemonize: detach from terminal, redirect stdio.
/// MUST be called BEFORE any tokio runtime is created.
#[cfg(unix)]
pub fn daemonize(pid_file: &PathBuf, log_file: &PathBuf) {
    // Ensure log directory exists
    if let Some(parent) = log_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // First fork
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("fork failed");
            process::exit(1);
        }
        0 => {}                // child continues
        _ => process::exit(0), // parent exits
    }

    // New session — detach from terminal
    if unsafe { libc::setsid() } == -1 {
        eprintln!("setsid failed");
        process::exit(1);
    }

    // Second fork — no longer session leader, can't reacquire terminal
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("second fork failed");
            process::exit(1);
        }
        0 => {} // grandchild continues
        _ => process::exit(0),
    }

    // Redirect stdio to log file
    let log = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open log file {:?}: {}", log_file, e);
            process::exit(1);
        }
    };
    use std::os::unix::io::AsRawFd;
    let log_fd = log.as_raw_fd();
    unsafe {
        libc::dup2(log_fd, 0); // stdin
        libc::dup2(log_fd, 1); // stdout
        libc::dup2(log_fd, 2); // stderr
    }
    drop(log);

    // Write PID file
    if let Some(parent) = pid_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(pid_file, process::id().to_string().as_bytes()) {
        eprintln!("Cannot write PID file {:?}: {}", pid_file, e);
        process::exit(1);
    }
}

/// Daemon mode is not available on non-Unix platforms.
/// Use the platform's native service manager instead (launchd, sc.exe, etc.).
#[cfg(all(not(unix), not(windows)))]
pub fn daemonize(_pid_file: &PathBuf, _log_file: &PathBuf) {
    eprintln!("--daemon is not supported on this platform. Use the native service manager.");
    process::exit(1);
}

/// Windows daemonize: spawn a detached child process (no console window),
/// then exit the parent.  The child detects it is already detached and
/// continues normally — equivalent to Unix double-fork semantics.
///
/// 平台注意：Windows 没有 SIGTERM/双 fork。`--stop` 走 taskkill（无 /F 无法终止
/// 控制台程序时会升级为 /F）。"注册为服务/计划任务"**不在桥内做** —— 用系统自带
/// 服务管理器（见 README 的平台说明）。
#[cfg(windows)]
pub fn daemonize(pid_file: &PathBuf, _log_file: &PathBuf) {
    extern "system" {
        fn GetConsoleWindow() -> isize;
    }

    // Guard: if already detached, we are the child — set up PID + logs
    if unsafe { GetConsoleWindow() } == 0 {
        // Write PID file
        if let Some(parent) = pid_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pid_file, process::id().to_string().as_bytes());
        // stdio 无需在此重定向：父进程已用 DETACHED_PROCESS + Stdio::null() 把子进程的
        // stdin/stdout/stderr 置空；日志由 init_tracing(daemon=true, log_file) 直接写文件。
        // （此处曾 OpenOptions 打开 log 又立刻 `let _ = log;` drop 句柄 —— 无效且误导, 已删。）
        if let Some(parent) = _log_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        return;
    }

    // Parent: respawn without a console window
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let exe = std::env::current_exe().expect("Cannot get executable path");
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Spawn detached child with all CLI args intact (including --daemon)
    std::process::Command::new(exe)
        .args(&args)
        .creation_flags(DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn detached background process");

    // Parent exits — child takes over
    process::exit(0);
}

// ── entry point ────────────────────────────────────────────────────────
// Daemonize BEFORE tokio runtime creation to avoid forking a live runtime.

pub fn main() {
    let cli = parse_args();

    // 一次性生命周期操作：不进 tokio 运行时、不 daemonize
    if cli.status || cli.stop || cli.check_config {
        let (def_pid, _def_log) = lifecycle::default_paths();
        let pid_file = cli.pid_file.clone().unwrap_or(def_pid);
        let code = if cli.status {
            lifecycle::status(&pid_file, cli.json)
        } else if cli.stop {
            lifecycle::stop(&pid_file, cli.json)
        } else {
            lifecycle::check_config(cli.config_path.as_deref(), cli.json)
        };
        std::process::exit(code);
    }

    // Resolve default paths (no tokio needed)
    let (def_pid, def_log) = lifecycle::default_paths();
    let pid_file = cli.pid_file.clone().unwrap_or(def_pid);
    let log_file = cli.log_file.clone().unwrap_or(def_log);

    // Daemonize before any tokio runtime exists
    if cli.daemon {
        daemonize(&pid_file, &log_file);
    }

    // Now it's safe to create the tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    rt.block_on(async {
        let result = async_main(cli, pid_file.clone(), log_file).await;
        // pid 文件归属(2026-09-20, 取代 AUDIT-1 A4):
        //   A4 当年"退出不删 pid"的理由是 —— deploy_bridge.start_bridge 靠 pid 文件在启动前
        //   杀陈旧进程, 删掉会让崩溃/重启后杀不掉(双实例风险)。
        //   桥现在自带 --status/--stop 且做 **PID 身份校验**, 陈旧 pid 改由"识别"而非"盲杀"处理;
        //   CLI 侧(P2, cli 11e866e)也已不再自行 kill 进程 ⇒ A4 的理由消失。
        //   新规则: **正常退出删除**(干净) · **异常/崩溃退出保留**(供 --status 报 stale-pid, 便于诊断)。
        match result {
            Ok(()) => {
                if let Err(e) = std::fs::remove_file(&pid_file) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(error = %e, "failed to remove pid file on shutdown");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Fatal error");
                std::process::exit(1);
            }
        }
    });
}

async fn async_main(
    cli: CliArgs,
    _pid_file: PathBuf,
    log_file: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Install ring as the default rustls crypto provider (must be done once at startup)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring crypto provider");

    let config = BridgeConfig::load(cli.config_path.as_deref())?;

    // Init tracing from config (aimail-gateway compatible)
    init_tracing(&config.logging, cli.daemon, &log_file);

    tracing::info!("aimail-bridge starting (pid={})", process::id());

    config.validate();
    let router = Arc::new(router::ProfileRouter::new(config.routes_file.clone()));
    router.load_from_file();

    if let Err(e) = router::start_routes_watcher(router.clone()) {
        tracing::warn!(error = %e, "Routes watcher failed to start — file edits won't hot-reload");
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                #[cfg(unix)]
                {
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                        Ok(mut sigterm) => sigterm.recv().await,
                        Err(e) => {
                            tracing::warn!(error = %e, "SIGTERM handler unavailable — falling back to SIGINT only");
                            Some(std::future::pending::<()>().await)
                        }
                    }
                }
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => {},
        }
        tracing::info!("Shutdown signal received, initiating graceful shutdown...");
        shutdown_clone.store(true, Ordering::SeqCst);
    });

    // Build admin router (always starts — health + route API)
    let admin_router = admin::build_admin_router(&config, router.clone());

    // Build the full app: admin routes + optional push webhook routes
    let app = if config.mode == "push" {
        let push_state = push::PushState {
            router: router.clone(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            config: config.clone(),
            forward_headers: config
                .forward_headers
                .iter()
                .filter_map(|h| axum::http::HeaderName::from_bytes(h.as_bytes()).ok())
                .collect(),
        };
        let push_router = push::build_push_router(push_state);
        admin_router.merge(push_router)
    } else if config.mode != "pull" {
        tracing::error!(mode = %config.mode, "Unknown mode. Use 'push' or 'pull'.");
        return Err(format!("Unknown mode: {} (fix aimail_bridge.toml)", config.mode).into());
    } else {
        admin_router
    };

    let app = crate::security::apply_security_headers(app);

    let sock_addr: std::net::SocketAddr = config.bind.parse()?;

    // TLS setup for push-mode inbound HTTPS (AUDIT-1, user requirement):
    // hostname is a domain → try static certs (tls_cert + tls_key),
    // else ACME auto-cert (Let's Encrypt, HTTP-01) — fall back to plain
    // HTTP with a warning if both fail.
    let tls_config: Option<axum_server::tls_rustls::RustlsConfig> = if config.mode == "push"
        && config.has_tls()
    {
        if let (Some(cert), Some(key)) = (config.tls_cert.as_deref(), config.tls_key.as_deref()) {
            match push::build_tls_config_from_paths(cert, key) {
                Ok(t) => {
                    tracing::info!("TLS enabled (static cert: {})", cert.display());
                    Some(t)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TLS cert load failed — falling back to plain HTTP");
                    None
                }
            }
        } else {
            // No static certs — try ACME auto-cert (referenced from
            // aimail-advanced's acme.rs implementation).
            match acme_tls_config(&config).await {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "ACME auto-cert failed — serving plain HTTP (hostname: {:?})",
                        config.hostname
                    );
                    None
                }
            }
        }
    } else {
        None
    };

    if config.mode == "pull" {
        // Route health check runs as a background task
        let health_router = router.clone();
        let health_config = config.health.clone();
        let health_shutdown = shutdown.clone();
        tokio::spawn(async move {
            health::start_route_health(health_router, health_config, health_shutdown).await;
        });
        let srv_task = start_http(app, sock_addr, shutdown.clone());
        // One pull loop per configured system (multi-system support).
        // Each loop has its own API key, system_id, dedup cache and backoff.
        // Loops are spawned as independent tasks so they run CONCURRENTLY
        // (sequentially awaiting infinite loops would starve all but the first).
        let first_err = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let mut pull_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let pull_systems = config.pull.resolved_systems();
        if pull_systems.is_empty() {
            // 未配置 pull 目标(等新对接填入)是合法状态: 不起循环, 也不报错。
            tracing::info!("no pull targets configured — pull loops disabled");
        }
        for sys in pull_systems {
            let r = router.clone();
            let sd = shutdown.clone();
            let fe = first_err.clone();
            pull_handles.push(tokio::spawn(async move {
                if let Err(e) = pull::start_pull_loop(sys, r, sd).await {
                    let mut guard = fe.lock().unwrap();
                    if guard.is_none() {
                        *guard = Some(e.to_string());
                    }
                }
            }));
        }
        let mut srv_fut = Box::pin(srv_task);
        if let Err(e) = (&mut srv_fut).await {
            *first_err.lock().unwrap() = Some(e.to_string());
        }
        for handle in pull_handles {
            let _ = handle.await;
        }
        let err_msg: Option<String> = {
            let mut guard = first_err.lock().unwrap();
            guard.take()
        };
        if let Some(msg) = err_msg {
            return Err(msg.into());
        }
    } else if let Some(tls) = tls_config {
        // Push mode with TLS → HTTPS server
        start_https(app, sock_addr, shutdown.clone(), tls).await?;
    } else {
        // Plain HTTP server (push without TLS, or pull admin API)
        start_http(app, sock_addr, shutdown.clone()).await?;
    }

    Ok(())
}

/// Try to build a TLS config via ACME auto-cert (Let's Encrypt HTTP-01).
///
/// Flow (mirrors aimail-advanced):
/// 1. cache dir = acme_cache or ~/.acme_cache
/// 2. existing cert < 60 days old → reuse
/// 3. else acquire via HTTP-01 (challenge_path → external server writes,
///    otherwise bridge's built-in port-80 listener)
/// 4. background renew task handles rotation
async fn acme_tls_config(
    config: &crate::config::BridgeConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    let domain = config
        .hostname
        .as_deref()
        .ok_or("ACME requires hostname (domain)")?;

    // Resolve cache dir to absolute — survives CWD changes after daemonize
    let cache_dir = match &config.acme_cache {
        Some(p) => {
            if p.is_absolute() {
                p.clone()
            } else {
                std::env::current_dir()?.join(p)
            }
        }
        None => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".acme_cache"),
    };

    let challenge_path = config
        .acme_challenge_path
        .as_deref()
        .and_then(|p| p.to_str());
    let email = config.acme_email.as_deref();

    // Pre-flight: if a challenge_path is configured it must be writable,
    // otherwise the HTTP-01 flow would fail mid-order (challenge written
    // only at set_ready time). Fail fast here instead (AUDIT-2).
    if let Some(dir) = challenge_path {
        let well_known = std::path::Path::new(dir)
            .join(".well-known")
            .join("acme-challenge");
        std::fs::create_dir_all(&well_known)?;
        let probe = well_known.join(".acme_probe");
        std::fs::write(&probe, b"1")?;
        let _ = std::fs::remove_file(&probe);
    }

    let (paths, _stop) = crate::acme::get_or_acquire_cert(
        domain,
        &cache_dir,
        email,
        challenge_path,
        None, // registry mode not used by bridge (single port)
    )
    .await?;

    // NOTE: the renew task keeps running; its stop token is intentionally
    // dropped here — the bridge runs until SIGTERM, and on exit the renew
    // task exits with the process. (Full clean-shutdown wiring would need
    // the stop token plumbed to the signal handler; acceptable for now.)
    push::build_tls_config_from_paths(&paths.cert, &paths.key)
}

/// Start a plain HTTP server with graceful shutdown.
async fn start_http(
    app: axum::Router,
    addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let shutdown_signal = async move {
        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await?;
    Ok(())
}

/// Start an HTTPS server (rustls) with graceful shutdown — push mode
/// inbound TLS support (AUDIT-1, user requirement 2026-08-16).
async fn start_https(
    app: axum::Router,
    addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    tls: axum_server::tls_rustls::RustlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("aimail-bridge serving HTTPS on {}", addr);
    let handle = axum_server::Handle::new();
    let shutdown_clone = shutdown.clone();
    let handle_clone = handle.clone();
    // Watch the shutdown flag and trigger graceful shutdown via the handle
    // (axum-server integrates graceful shutdown into its accept loop; we
    // only need to signal it).
    tokio::spawn(async move {
        loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                handle_clone.graceful_shutdown(None);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;
    Ok(())
}

/// Initialize tracing subscriber from LoggingConfig (aimail-gateway compatible).
/// When daemon mode is active, log file from CLI args takes precedence.
fn init_tracing(cfg: &crate::config::LoggingConfig, daemon: bool, daemon_log: &std::path::Path) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    // Determine log destination: daemon log file > config log file > stdout
    let writer: Box<dyn std::io::Write + Send> = if daemon {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(daemon_log)
            .unwrap_or_else(|e| panic!("failed to open daemon log file {:?}: {}", daemon_log, e));
        Box::new(file)
    } else if let Some(ref path) = cfg.file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("failed to open log file {:?}: {}", path, e));
        Box::new(file)
    } else {
        Box::new(std::io::stdout())
    };

    let (non_blocking, _guard) = tracing_appender::non_blocking(writer);
    builder.with_writer(non_blocking).init();
    std::mem::forget(_guard);
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn test_parse_args_default() {
        let cli = parse_args_from(&["aimail-bridge".into()]);
        assert!(!cli.daemon);
        assert!(cli.pid_file.is_none());
        assert!(cli.log_file.is_none());
        assert!(cli.config_path.is_none());
    }

    #[test]
    fn test_parse_args_daemon() {
        let cli = parse_args_from(&["aimail-bridge".into(), "--daemon".into()]);
        assert!(cli.daemon);
    }

    #[test]
    fn test_parse_args_config() {
        let cli = parse_args_from(&["aimail-bridge".into(), "-c".into(), "/tmp/test.toml".into()]);
        assert_eq!(cli.config_path, Some(PathBuf::from("/tmp/test.toml")));
    }

    #[test]
    fn test_parse_args_pid_file() {
        let cli = parse_args_from(&[
            "aimail-bridge".into(),
            "--pid-file".into(),
            "/var/run/bridge.pid".into(),
        ]);
        assert_eq!(cli.pid_file, Some(PathBuf::from("/var/run/bridge.pid")));
    }

    #[test]
    fn test_parse_args_log_file() {
        let cli = parse_args_from(&[
            "aimail-bridge".into(),
            "--log-file".into(),
            "/var/log/bridge.log".into(),
        ]);
        assert_eq!(cli.log_file, Some(PathBuf::from("/var/log/bridge.log")));
    }
}

/// Parse CLI arguments from a custom args slice (testable).
pub fn parse_args_from(args: &[String]) -> CliArgs {
    let mut cli = CliArgs::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--daemon" | "-d" => cli.daemon = true,
            "--pid-file" => {
                i += 1;
                cli.pid_file = Some(PathBuf::from(&args[i]));
            }
            "--log-file" => {
                i += 1;
                cli.log_file = Some(PathBuf::from(&args[i]));
            }
            "--config" | "-c" => {
                i += 1;
                cli.config_path = Some(PathBuf::from(&args[i]));
            }
            _ => {}
        }
        i += 1;
    }
    cli
}
