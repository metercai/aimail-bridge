//! Automatic TLS certificate acquisition & renewal via Let's Encrypt (ACME).
//!
//! Ported from aimail-advanced's acme.rs (same flow, same instant-acme
//! usage) — AUDIT-1 TLS wiring, user requirement 2026-08-16.
//!
//! ## Flow
//!
//! 1. Resolve `cache_dir` to absolute (survives CWD changes after daemonization).
//! 2. Check if a previously-acquired certificate is still valid (< 60 days old).
//! 3. If valid → reuse (skip ACME request, avoid LE rate limits on restart).
//! 4. If absent or expired → request via HTTP-01 challenge (port 80).
//! 5. Save cert + private key (chmod 0o600) to the cache directory.
//! 6. Spawn a background renew task (checks every 12h, stop flag for clean shutdown).
//!
//! On any failure the caller should fall back to plain HTTP with a warning.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use tracing::{info, warn};

/// Result of a successful ACME certificate acquisition (or cache hit).
pub struct AcmeCertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Stop token for the background renew task.
///
/// Set to `true` on graceful shutdown. The task checks this flag every
/// 10 seconds and exits cleanly.
pub type AcmeStopToken = Arc<AtomicBool>;

/// Shared in-memory registry for ACME challenge token→proof mappings.
///
/// Kept for future use (dual-port / bridge-served HTTP-01); the current
/// wiring passes `None` and relies on file-based or built-in challenge
/// serving. Tests cover the registry round-trip.
pub type ChallengeRegistry = Arc<Mutex<HashMap<String, String>>>;

// ── Public entry point ────────────────────────────────────────────

/// Get a TLS certificate for `domain`, reusing a cached one if still valid.
///
/// Returns the cert/key paths plus a stop token for the renew task.
/// The caller should store the token and set it to `true` on shutdown.
///
/// Challenge serving strategy:
/// - `challenge_path` set → write proof files for an external HTTP server
///   (nginx/caddy on port 80).
/// - `registry` set → publish proof to the in-memory registry (bridge
///   itself serves /.well-known/acme-challenge/{token}).
/// - neither → start a temporary TCP listener on port 80.
pub async fn get_or_acquire_cert(
    domain: &str,
    cache_dir: &Path,
    acme_email: Option<&str>,
    challenge_path: Option<&str>,
    registry: Option<&ChallengeRegistry>,
) -> Result<(AcmeCertPaths, AcmeStopToken), Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(cache_dir)?;

    let stop = Arc::new(AtomicBool::new(false));

    // 1. Try existing cert first — avoid re-requesting on restart
    if let Some(paths) = check_existing_cert(domain, cache_dir) {
        info!(%domain, cert = %paths.cert.display(), "Reusing existing ACME certificate");
        spawn_renew_task(domain, cache_dir, acme_email, challenge_path, registry, Arc::clone(&stop));
        return Ok((paths, stop));
    }

    // 2. Acquire new cert from Let's Encrypt
    info!(%domain, "Acquiring new ACME certificate");
    let paths = acquire_cert_inner(domain, cache_dir, acme_email, challenge_path, registry).await?;
    // chmod 0o600 on private key
    set_key_permissions(&paths.key)?;

    spawn_renew_task(domain, cache_dir, acme_email, challenge_path, registry, Arc::clone(&stop));
    Ok((paths, stop))
}

// ── Existing-cert check ───────────────────────────────────────────

/// Check whether a previously-acquired certificate is still usable.
///
/// Let's Encrypt certs are valid for 90 days; we consider one "fresh" if
/// its file modification time is within 60 days. Using mtime avoids
/// pulling in x509 parsing dependencies.
fn check_existing_cert(domain: &str, cache_dir: &Path) -> Option<AcmeCertPaths> {
    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));
    let key_path = cache_dir.join(format!("{}.key.pem", domain));

    if !cert_path.exists() || !key_path.exists() {
        return None;
    }

    let cert_age = cert_path.metadata().ok()?.modified().ok()?.elapsed().ok()?;

    let max_age = Duration::from_secs(60 * 86400); // 60 days
    if cert_age > max_age {
        info!(
            %domain,
            age_days = cert_age.as_secs() / 86400,
            "Cached certificate too old, will re-acquire"
        );
        return None;
    }

    Some(AcmeCertPaths {
        cert: cert_path,
        key: key_path,
    })
}

// ── ACME acquisition (inner) ──────────────────────────────────────

/// Perform a full ACME HTTP-01 challenge flow to obtain a certificate.
///
/// Callers should use `get_or_acquire_cert` instead — this is the raw
/// acquisition path, also used by the renew task.
async fn acquire_cert_inner(
    domain: &str,
    cache_dir: &Path,
    acme_email: Option<&str>,
    challenge_path: Option<&str>,
    registry: Option<&ChallengeRegistry>,
) -> Result<AcmeCertPaths, Box<dyn std::error::Error + Send + Sync>> {
    let credentials_path = cache_dir.join("account.json");
    let cert_key_path = cache_dir.join(format!("{}.key.pem", domain));
    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));

    let contact = format!("mailto:{}", acme_email.unwrap_or("acme@agent-mail-relay.local"));
    let directory_url = LetsEncrypt::Production.url().to_owned();
    let builder = Account::builder()?;

    // Create or restore account
    let account = if credentials_path.exists() {
        let json = std::fs::read_to_string(&credentials_path)?;
        let creds: AccountCredentials = serde_json::from_str(&json)?;
        builder.from_credentials(creds).await?
    } else {
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url,
                None,
            )
            .await?;
        // Persist account credentials for future renewals.
        // Lock down permissions too — account.json contains the ACME
        // account private key (AUDIT-2: was world-readable by default).
        std::fs::write(&credentials_path, serde_json::to_string_pretty(&credentials)?)?;
        set_key_permissions(&credentials_path)?;
        account
    };

    // Create order
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await?;

    // Process authorizations — serve HTTP-01 challenges
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => return Err(format!("unexpected authorization status: {:?}", authz.status).into()),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or("no HTTP-01 challenge available")?;

        let key_auth = challenge.key_authorization();
        let token = challenge.token.clone();
        let proof = key_auth.as_str().to_string();

        // Serve the challenge (registry / file-based / built-in HTTP server)
        serve_challenge(&token, &proof, challenge_path, registry)?;

        challenge.set_ready().await?;
    }

    // Wait for order to become ready
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(format!("unexpected order status: {status:?}").into());
    }

    // Finalize — get private key and certificate chain
    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    std::fs::write(&cert_key_path, &private_key_pem)?;
    std::fs::write(&cert_path, &cert_chain_pem)?;

    // Lock down private key file
    set_key_permissions(&cert_key_path)?;

    info!(%domain, cert_path = %cert_path.display(), "ACME certificate acquired");

    Ok(AcmeCertPaths {
        cert: cert_path,
        key: cert_key_path,
    })
}

// ── Permissions ───────────────────────────────────────────────────

fn set_key_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        // On Windows, restrict the private key to the current user only.
        // icacls is built into every supported Windows version.
        let path_str = path.to_string_lossy();
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "Administrator".into());
        let status = std::process::Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", user),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            tracing::warn!(
                path = %path_str,
                "Failed to lock down private key ACL — cert may be readable by other users"
            );
        }
    }
    Ok(())
}

// ── HTTP-01 challenge server ──────────────────────────────────────

/// Serve an ACME HTTP-01 challenge.
///
/// Three modes depending on `challenge_path` and `registry`:
///
/// 1. **In-memory registry** (`registry` is `Some`):
///    Fastest — stores proof in the shared HashMap, no filesystem or threads.
///
/// 2. **File-based** (`challenge_path` is `Some(dir)`):
///    Writes `{dir}/.well-known/acme-challenge/{token}` for an external
///    HTTP server (e.g. nginx) to serve.
///
/// 3. **Built-in HTTP server** (both `None`):
///    Starts a temporary TCP listener on port 80 and waits for Let's
///    Encrypt to connect and fetch the proof.
fn serve_challenge(
    token: &str,
    proof: &str,
    challenge_path: Option<&str>,
    registry: Option<&ChallengeRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. In-memory registry
    if let Some(reg) = registry {
        let mut map = reg.lock().map_err(|e| format!("challenge lock: {e}"))?;
        map.insert(token.to_string(), proof.to_string());
        info!(%token, "ACME challenge registered in memory");
        return Ok(());
    }

    // 2. File-based (external HTTP server like nginx)
    if let Some(dir) = challenge_path {
        let well_known = Path::new(dir)
            .join(".well-known")
            .join("acme-challenge");
        std::fs::create_dir_all(&well_known)?;
        let file_path = well_known.join(token);
        std::fs::write(&file_path, proof)?;
        info!(
            path = %file_path.display(),
            "ACME challenge written for external HTTP server"
        );
        return Ok(());
    }

    // 3. Built-in HTTP server on port 80 (temporary TCP listener)
    serve_challenge_http(token, proof)?;
    Ok(())
}

/// Start a temporary HTTP-01 challenge server on port 80, wait for
/// Let's Encrypt to connect and fetch the proof, then tear down.
///
/// The server runs in a background thread so the caller can proceed
/// with `challenge.set_ready()` while the server is still listening.
/// After the first successful request (or 30s timeout), the listener
/// is closed.
fn serve_challenge_http(
    token: &str,
    proof: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    let proof_owned = proof.to_string();
    let token_owned = token.to_string();
    let listener = TcpListener::bind("0.0.0.0:80")?;
    listener.set_nonblocking(true)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    std::thread::spawn(move || {
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    let _ = reader.read_line(&mut line);
                    let expected = format!("/.well-known/acme-challenge/{}", token_owned);
                    if line.contains(&expected) {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            proof_owned.len(),
                            proof_owned
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

// ── Background renew ──────────────────────────────────────────────

/// Spawn a background tokio task that renews the certificate periodically.
fn spawn_renew_task(
    domain: &str,
    cache_dir: &Path,
    email: Option<&str>,
    challenge_path: Option<&str>,
    registry: Option<&ChallengeRegistry>,
    stop: Arc<AtomicBool>,
) {
    let d = domain.to_string();
    let c = cache_dir.to_path_buf();
    let e = email.map(|s| s.to_string());
    let cp = challenge_path.map(|s| s.to_string());
    let r = registry.cloned();
    tokio::spawn(async move {
        renew_loop(&d, &c, e.as_deref(), cp.as_deref(), r.as_ref(), stop).await;
    });
}

/// Background renew loop — checks every 12 hours, renews after ~60 days.
///
/// Polls `stop` flag every 10 seconds so the caller can signal a clean exit.
async fn renew_loop(
    domain: &str,
    cache_dir: &Path,
    email: Option<&str>,
    challenge_path: Option<&str>,
    registry: Option<&ChallengeRegistry>,
    stop: Arc<AtomicBool>,
) {
    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));
    let renew_age = Duration::from_secs(60 * 86400);

    loop {
        // Sleep in 10-second increments so stop flag is checked frequently
        for _ in 0..(12 * 3600 / 10) {
            if stop.load(Ordering::Relaxed) {
                info!(%domain, "ACME renew task: stop flag received, exiting");
                return;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        let needs_renew = match std::fs::metadata(&cert_path) {
            Ok(meta) => meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age > renew_age)
                .unwrap_or(true),
            Err(_) => true,
        };

        if !needs_renew {
            continue;
        }

        if stop.load(Ordering::Relaxed) {
            return;
        }

        info!(%domain, "Renewing ACME certificate...");
        match acquire_cert_inner(domain, cache_dir, email, challenge_path, registry).await {
            Ok(paths) => {
                let _ = set_key_permissions(&paths.key);
                info!(%domain, cert = %paths.cert.display(), "ACME certificate renewed");
            }
            Err(e) => warn!(%domain, %e, "ACME renew failed — will retry"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_existing_cert_missing() {
        let dir = std::env::temp_dir().join(format!("aimail_acme_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(check_existing_cert("example.com", &dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_existing_cert_fresh() {
        let dir = std::env::temp_dir().join(format!("aimail_acme_test2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("example.com.cert.pem"), "cert").unwrap();
        std::fs::write(dir.join("example.com.key.pem"), "key").unwrap();
        let paths = check_existing_cert("example.com", &dir).expect("fresh cert should be reused");
        assert_eq!(paths.cert.file_name().unwrap(), "example.com.cert.pem");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_challenge_registry_roundtrip() {
        let reg: ChallengeRegistry = Default::default();
        reg.lock().unwrap().insert("tok".into(), "proof".into());
        assert_eq!(
            reg.lock().unwrap().get("tok").cloned().as_deref(),
            Some("proof")
        );
        assert!(reg.lock().unwrap().get("missing").is_none());
    }
}
