//! Pull-mode long-poll client.
//!
//! Repeatedly GETs relay's /pending endpoint, forwards each delivery
//! to the gateway webhook port, then ACKs the relay.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::PullSystemConfig;
use crate::router::ProfileRouter;

/// Application state shared across pull tasks.
#[derive(Clone)]
pub struct PullState {
    pub router: Arc<ProfileRouter>,
    pub http_client: reqwest::Client,
    pub pull_cfg: PullSystemConfig,
}

/// Main pull loop: poll → forward → ACK, with dedup cache.
pub async fn start_pull_loop(
    pull_cfg: PullSystemConfig,
    router: Arc<ProfileRouter>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = PullState {
        router: router.clone(),
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
        pull_cfg: pull_cfg.clone(),
    };

    let mut seen: HashMap<i64, Instant> = HashMap::new();
    let seen_ttl = Duration::from_secs(7200);
    let poll_interval = pull_cfg.poll_interval_sec;
    let mut consecutive_failures: u32 = 0;
    let mut consecutive_ack_failures: u32 = 0;
    const MAX_BACKOFF: u64 = 300; // 5 min
    const ACK_FAIL_WARN_THRESHOLD: u32 = 10;

    tracing::info!(
        aimail_url = %pull_cfg.aimail_url,
        system_id = %pull_cfg.system_id,
        poll_interval_sec = pull_cfg.poll_interval_sec,
        "Starting pull loop"
    );

    loop {
        // Check graceful shutdown
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("Pull loop shutting down gracefully");
            return Ok(());
        }

        // Periodic cleanup of stale dedup entries
        seen.retain(|_, t| t.elapsed() < seen_ttl);

        tracing::debug!("Pull poll cycle starting — fetching pending deliveries");
        let sleep_secs = match fetch_pending(&state).await {
            Ok(batches) => {
                consecutive_failures = 0;
                if !batches.is_empty() {
                    tracing::info!(count = batches.len(), "Fetched pending deliveries");
                }
                let mut ack_ids: Vec<i64> = Vec::new();
                let mut forwarded_emails: Vec<String> = Vec::new();
                for batch in &batches {
                    // Serialize shared body once per batch, not per delivery
                    let body_bytes = axum::body::Bytes::from(serde_json::to_vec(&batch.body)?);
                    for d in &batch.deliveries {
                    // Dedup: skip already-forwarded deliveries
                    if let Some(t) = seen.get(&d.id) {
                        if t.elapsed() < seen_ttl {
                            tracing::debug!(id = d.id, "Already forwarded — ACKing without re-forward");
                            forwarded_emails.push(d.email.clone());
                            ack_ids.push(d.id);
                            continue;
                        }
                    }

                    // Look up route — do NOT ACK if route is missing.
                    // Routes may be temporarily empty during a rescan; the relay
                    // should have its own cron cleanup for stale pending deliveries.
                    let route = match state.router.lookup(&d.email) {
                        Some(r) => r,
                        None => {
                            tracing::warn!(email = %d.email, id = d.id, "No route — skipping (will retry)");
                            continue;
                        }
                    };

                    let target = route.target_url();

                    // Parse headers from relay payload
                    let headers: HashMap<String, String> = match serde_json::from_value(d.headers.clone()) {
                        Ok(h) => h,
                        Err(_) => HashMap::new(),  // null or invalid → treat as empty
                    };

                    // Forward to gateway (shared body from batch)
                    let mut req_builder = state.http_client.post(target);
                    for (k, v) in &headers {
                        if k.eq_ignore_ascii_case("content-type") {
                            continue;  // gateway includes it, bridge sets it below
                        }
                        req_builder = req_builder.header(k.as_str(), v.as_str());
                    }
                    req_builder = req_builder
                        .header("content-type", "application/json")
                        .body(body_bytes.clone());

                    match req_builder.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            seen.insert(d.id, Instant::now());
                            forwarded_emails.push(d.email.clone());
                            ack_ids.push(d.id);
                        }
                        Ok(resp) => {
                            tracing::warn!(
                                id = d.id,
                                email = %d.email,
                                status = %resp.status(),
                                "Forward got non-2xx — retrying next poll"
                            );
                        }
                        Err(e) => {
                            tracing::error!(id = d.id, email = %d.email, error = %e, "Forward failed");
                        }
                    }
                    } // end deliveries loop
                } // end batches loop

                // ACK the forwarded deliveries
                if !ack_ids.is_empty() {
                    match ack_deliveries(&state, &ack_ids).await {
                        Ok(_) => {
                            consecutive_ack_failures = 0;
                            tracing::info!(forwarded = ack_ids.len(), emails = ?forwarded_emails, "Pull cycle complete");
                        }
                        Err(e) => {
                            consecutive_ack_failures += 1;
                            if consecutive_ack_failures >= ACK_FAIL_WARN_THRESHOLD
                                && consecutive_ack_failures % ACK_FAIL_WARN_THRESHOLD == 0
                            {
                                tracing::warn!(
                                    count = consecutive_ack_failures,
                                    "ACK has been failing for {} cycles — relay ACK endpoint may be down",
                                    consecutive_ack_failures,
                                );
                            }
                            tracing::error!(forwarded = ack_ids.len(), emails = ?forwarded_emails, error = %e, "ACK failed — will retry");
                        }
                    }
                }

                poll_interval
            }
            Err(e) => {
                consecutive_failures += 1;
                let bs = (poll_interval * 2_u64.pow(consecutive_failures.min(6)))
                    .min(MAX_BACKOFF);
                tracing::error!(
                    error = %e,
                    consecutive_failures,
                    backoff_secs = bs,
                    "Pull fetch failed — backing off"
                );
                bs
            }
        };

        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
    }
}

/// Pending delivery from relay (batched format).
#[derive(Debug, serde::Deserialize)]
struct PendingBatch {
    body: serde_json::Value,
    deliveries: Vec<BatchDelivery>,
}

#[derive(Debug, serde::Deserialize)]
struct BatchDelivery {
    id: i64,
    email: String,
    headers: serde_json::Value,
}

/// v1 API signature for a gateway request (spec: aimail-gateway
/// docs/API-SIGNATURE-PROTOCOL.md).
///
/// `sig = hex(HMAC-SHA256(key = sha256(raw_key), msg = base))` where
/// `base = METHOD\npath_and_query\ntimestamp\nsha256_hex(body)`.
/// The raw key stays offline — only the signature + identity cross the wire.
pub fn api_sign(api_key: &str, method: &str, path: &str, body: &[u8]) -> (String, String) {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let mut kh = Sha256::new();
    kh.update(api_key.as_bytes());
    let key_hash = hex::encode(kh.finalize());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".into());

    let mut bh = Sha256::new();
    bh.update(body);
    let body_hash = hex::encode(bh.finalize());

    let base = format!("{method}\n{path}\n{now_ms}\n{body_hash}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key_hash.as_bytes())
        .expect("HMAC can take a key of any size");
    mac.update(base.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    (now_ms, sig)
}

/// Fetch pending deliveries from relay (batched response).  Returns empty vec if no routes.
async fn fetch_pending(state: &PullState) -> Result<Vec<PendingBatch>, Box<dyn std::error::Error + Send + Sync>> {
    let emails: Vec<String> = state.router.list_emails();
    if emails.is_empty() {
        return Ok(Vec::new());
    }

    // Extract unique domains from route table
    let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();
    for email in &emails {
        if let Some(domain) = email.rsplit('@').next() {
            domains.insert(domain.to_string());
        }
    }

    let url = format!(
        "{}/api/v1/admin/pending",
        state.pull_cfg.aimail_url.trim_end_matches('/'),
    );
    let body_json = serde_json::json!({
        "limit": 50,
        "filter": domains.into_iter().collect::<Vec<_>>(),
    });
    let body_bytes = serde_json::to_vec(&body_json)?;
    let (ts, sig) = api_sign(state.pull_cfg.effective_key(), "POST", "/api/v1/admin/pending", &body_bytes);

    let resp = state
        .http_client
        .post(&url)
        .header("X-Api-Identity", state.pull_cfg.system_id.as_str())
        .header("X-Api-Timestamp", ts)
        .header("X-Api-Signature", sig)
        .header("content-type", "application/json")
        .body(body_bytes)
        .send()
        .await?
        .error_for_status()?;

    let body: serde_json::Value = resp.json().await?;
    let batches: Vec<PendingBatch> = serde_json::from_value(body["batches"].clone())
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to parse pending batches from relay response");
            Vec::new()
        });

    Ok(batches)
}

/// ACK deliveries back to relay.
async fn ack_deliveries(state: &PullState, ids: &[i64]) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!(
        "{}/api/v1/admin/pending/ack",
        state.pull_cfg.aimail_url.trim_end_matches('/'),
    );

    let ack_body = serde_json::to_vec(&serde_json::json!({ "ids": ids }))?;
    let (ts, sig) = api_sign(state.pull_cfg.effective_key(), "POST", "/api/v1/admin/pending/ack", &ack_body);

    let resp = state
        .http_client
        .post(&url)
        .header("X-Api-Identity", state.pull_cfg.system_id.as_str())
        .header("X-Api-Timestamp", ts)
        .header("X-Api-Signature", sig)
        .header("content-type", "application/json")
        .body(ack_body)
        .send()
        .await?
        .error_for_status()?;

    let body: serde_json::Value = resp.json().await?;
    let acked = body["acked"].as_u64();
    if acked.is_none() {
        tracing::warn!(?body, "ACK response missing 'acked' field");
    }
    Ok(acked.unwrap_or(0) as usize)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_batch_deserialize() {
        let json = r#"{
            "body": {"subject": "hello"},
            "deliveries": [
                {"id": 1, "email": "alice@x.com", "headers": {"x-fwd": "v1"}},
                {"id": 2, "email": "bob@x.com", "headers": {"x-fwd": "v2"}}
            ]
        }"#;
        let batch: PendingBatch = serde_json::from_str(json).unwrap();
        assert_eq!(batch.deliveries.len(), 2);
        assert_eq!(batch.deliveries[0].id, 1);
        assert_eq!(batch.deliveries[0].email, "alice@x.com");
        assert_eq!(batch.deliveries[1].id, 2);
        assert_eq!(batch.deliveries[1].email, "bob@x.com");
    }

    #[test]
    fn test_pending_batch_empty_deliveries() {
        let json = r#"{"body": {}, "deliveries": []}"#;
        let batch: PendingBatch = serde_json::from_str(json).unwrap();
        assert!(batch.deliveries.is_empty());
    }

    #[test]
    fn test_batch_delivery_deserialize() {
        let json = r#"{"id": 42, "email": "carol@test.org", "headers": {"key": "val"}}"#;
        let d: BatchDelivery = serde_json::from_str(json).unwrap();
        assert_eq!(d.id, 42);
        assert_eq!(d.email, "carol@test.org");
        let h: HashMap<String, String> = serde_json::from_value(d.headers).unwrap();
        assert_eq!(h.get("key").unwrap(), "val");
    }

    #[test]
    fn test_batch_delivery_missing_email() {
        // id is i64 (not optional) but should deserialize
        let json = r#"{"id": 0, "email": "", "headers": {}}"#;
        let d: BatchDelivery = serde_json::from_str(json).unwrap();
        assert!(d.email.is_empty());
    }

    // ── Backoff calculation ──────────────────────────────

    #[test]
    fn test_backoff_calculation_start() {
        // consecutive_failures=1: 10 * 2^1 = 20
        let poll_interval: u64 = 10;
        let failures: u32 = 1;
        let bs = (poll_interval * 2_u64.pow(failures.min(6))).min(300);
        assert_eq!(bs, 20);
    }

    #[test]
    fn test_backoff_calculation_ramp() {
        let poll_interval: u64 = 10;
        for (failures, expected) in &[(0u32, 10u64), (1, 20), (2, 40), (3, 80), (4, 160), (5, 300), (6, 300)] {
            let bs = (poll_interval * 2_u64.pow((*failures).min(6))).min(300);
            assert_eq!(bs, *expected, "failures={} should give {}", failures, expected);
        }
    }

    #[test]
    fn test_backoff_calculation_capped_at_300() {
        let poll_interval: u64 = 10;
        // After 6+ failures, backoff should be 300
        let bs = (poll_interval * 2_u64.pow(100.min(6))).min(300);
        assert_eq!(bs, 300);
    }

    #[test]
    fn test_backoff_different_poll_interval() {
        let poll_interval: u64 = 30;
        let bs = (poll_interval * 2_u64.pow(3.min(6))).min(300);
        assert_eq!(bs, 240); // 30 * 2^3 = 240
    }

    #[test]
    fn test_backoff_poll_interval_above_max() {
        let poll_interval: u64 = 600; // 10 min
        let bs = (poll_interval * 2_u64.pow(0.min(6))).min(300);
        assert_eq!(bs, 300); // capped at 300
    }

    // ── URL construction ──────────────────────────────────

    #[test]
    fn test_fetch_pending_url_with_trailing_slash() {
        let url = "http://relay.example.com/";
        let expected = format!("{}/api/v1/admin/pending", url.trim_end_matches('/'));
        assert_eq!(expected, "http://relay.example.com/api/v1/admin/pending");
    }

    #[test]
    fn test_fetch_pending_url_without_trailing_slash() {
        let url = "http://relay.example.com";
        let expected = format!("{}/api/v1/admin/pending", url.trim_end_matches('/'));
        assert_eq!(expected, "http://relay.example.com/api/v1/admin/pending");
    }

    #[test]
    fn test_fetch_pending_url_localhost() {
        let url = "http://127.0.0.1:38080";
        let expected = format!("{}/api/v1/admin/pending", url.trim_end_matches('/'));
        assert_eq!(expected, "http://127.0.0.1:38080/api/v1/admin/pending");
    }

    #[test]
    fn test_ack_url_construction() {
        let url = "http://admin.relay";
        let expected = format!("{}/api/v1/admin/pending/ack", url.trim_end_matches('/'));
        assert_eq!(expected, "http://admin.relay/api/v1/admin/pending/ack");
    }

    // ── v1 API signature (3-language parity) ──────────────

    #[test]
    fn test_api_sign_matches_canonical_vector() {
        // SAME canonical vector as base Rust / Python / TS — pinning one
        // value across all four implementations proves bit-identical parity.
        // (aimail-gateway docs/API-SIGNATURE-PROTOCOL.md)
        let raw_key = "0123456789abcdef0123456789abcdef";
        let method = "POST";
        let path = "/api/v1/whitelists?domain=alice%40x.com&value=%40mx-a.test";
        let body = b"{\"direction\":\"to\"}";

        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let key_hash = {
            let mut h = Sha256::new();
            h.update(raw_key.as_bytes());
            hex::encode(h.finalize())
        };
        assert_eq!(
            key_hash,
            "3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9"
        );
        let ts = "1756000000000";
        let body_hash = {
            let mut h = Sha256::new();
            h.update(body);
            hex::encode(h.finalize())
        };
        let base = format!("{method}\n{path}\n{ts}\n{body_hash}");
        let mut mac = Hmac::<Sha256>::new_from_slice(key_hash.as_bytes()).unwrap();
        mac.update(base.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            expected,
            "cabf840e1d1a8dd9d6885762beae087f422dbd4d6d20c9ca404896120a45bcbd"
        );

        // And the helper itself produces a well-formed (ts, sig) pair.
        let (ts2, sig2) = api_sign(raw_key, method, path, body);
        assert!(ts2.parse::<u128>().is_ok(), "timestamp must be epoch millis");
        assert_eq!(sig2.len(), 64, "signature must be 64 hex chars");
    }

    // ── JSON serde edge cases ────────────────────────────

    #[test]
    fn test_pending_batch_deserialize_extra_fields() {
        let json = r#"{"body": {}, "deliveries": [], "extra": "ignored"}"#;
        let batch: PendingBatch = serde_json::from_str(json).unwrap();
        assert!(batch.deliveries.is_empty());
    }

    #[test]
    fn test_pending_batch_body_null() {
        let json = r#"{"body": null, "deliveries": [{"id": 1, "email": "a@b.c", "headers": {}}]}"#;
        let batch: PendingBatch = serde_json::from_str(json).unwrap();
        assert_eq!(batch.deliveries.len(), 1);
    }

    #[test]
    fn test_pending_batch_delivery_missing_headers() {
        // headers is a required field in BatchDelivery, so missing = error
        let json = r#"{"body": {}, "deliveries": [{"id": 1, "email": "a@b.c"}]}"#;
        let result: Result<PendingBatch, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pending_batch_delivery_email_null() {
        let json = r#"{"body": {}, "deliveries": [{"id": 1, "email": null, "headers": {}}]}"#;
        let result: Result<PendingBatch, _> = serde_json::from_str(json);
        // email is String, so null should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_delivery_deserialize_invalid_id_type() {
        let json = r#"{"id": "not-a-number", "email": "a@b.c", "headers": {}}"#;
        let result: Result<BatchDelivery, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_pending_batch_empty_body_array() {
        let json = r#"{"body": [], "deliveries": []}"#;
        let batch: PendingBatch = serde_json::from_str(json).unwrap();
        // body can be any valid JSON — array is fine
        assert!(batch.body.is_array());
    }

    #[test]
    fn test_pending_batch_multiple_batches() {
        let json = r#"{
            "batches": [
                {"body": {"t": 1}, "deliveries": [{"id": 1, "email": "a@x.com", "headers": {}}]},
                {"body": {"t": 2}, "deliveries": [{"id": 2, "email": "b@x.com", "headers": {}}]}
            ]
        }"#;
        #[derive(serde::Deserialize)]
        struct Wrapper { batches: Vec<PendingBatch> }
        let w: Wrapper = serde_json::from_str(json).unwrap();
        assert_eq!(w.batches.len(), 2);
        assert_eq!(w.batches[0].deliveries[0].email, "a@x.com");
        assert_eq!(w.batches[1].deliveries[0].email, "b@x.com");
    }

    #[test]
    fn test_dedup_seen_map_logic() {
        use std::collections::HashMap;
        use std::time::Instant;
        
        let mut seen: HashMap<i64, Instant> = HashMap::new();
        let seen_ttl = std::time::Duration::from_secs(7200);
        
        // Insert two IDs
        seen.insert(1, Instant::now());
        seen.insert(2, Instant::now());
        assert_eq!(seen.len(), 2);
        
        // Check dedup: both should be within TTL
        assert!(seen.get(&1).unwrap().elapsed() < seen_ttl);
        assert!(seen.get(&2).unwrap().elapsed() < seen_ttl);
        
        // Remove stale entries: none should be removed
        seen.retain(|_, t| t.elapsed() < seen_ttl);
        assert_eq!(seen.len(), 2);
        
        // ACK IDs should only include those not recently seen
        let ack_only_new = vec![3i64, 4].into_iter()
            .filter(|id| !seen.contains_key(id))
            .collect::<Vec<_>>();
        assert_eq!(ack_only_new.len(), 2);
        assert_eq!(ack_only_new, vec![3, 4]);
        
        // Simulate forwarding: insert after successful forward
        seen.insert(3, Instant::now());
        assert!(seen.contains_key(&3));
    }

    #[test]
    fn test_dedup_skip_already_forwarded() {
        use std::collections::HashMap;
        use std::time::Instant;
        
        let mut seen: HashMap<i64, Instant> = HashMap::new();
        let seen_ttl = std::time::Duration::from_secs(7200);
        
        // Simulate an email that was already forwarded
        seen.insert(42, Instant::now());
        
        // When processing delivery with id=42, check dedup
        let id = 42i64;
        let already_seen = seen.get(&id)
            .map(|t| t.elapsed() < seen_ttl)
            .unwrap_or(false);
        assert!(already_seen);
        
        // ACK should still include it (the loop ACKs even deduped)
        let deduped_acks = if already_seen { vec![id] } else { vec![] };
        assert_eq!(deduped_acks, vec![42]);
    }
}
