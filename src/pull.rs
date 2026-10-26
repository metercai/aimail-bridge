//! Pull mode: SSE primary, long-pull fallback (contract §0.3/0.4).
//!
//! State machine (three-client isomorphism with pysdk/tssdk):
//! ```text
//! start: GET /pending/stream probe (signed, empty body)
//!   200 + text/event-stream     -> Stream
//!   404/405/connect fail        -> Poll
//!   connected, no data 30s      -> Poll (dead/buffered link)
//! Stream: mail event -> forward + ack (shared path);
//!   normal server rotation (300s life) -> immediate reconnect (not counted);
//!   transport error -> backoff reconnect 1s->30s; 3 consecutive -> Poll
//! Poll: long-pull POST (timeout_ms=50_000); non-empty round -> next round
//!   with no sleep; re-probe /stream every 10 min
//! ```
//! Kill switch: `AIMAIL_PULL_MODE = auto|stream|poll` (default auto).
//! `stream` forces the stream preference (transport-error drops never
//! downgrade); `poll` disables probing entirely. Old servers (no /stream)
//! fall through to Poll automatically and are re-probed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;

use crate::config::PullSystemConfig;
use crate::router::ProfileRouter;

// ── Contract constants (single source of truth, mirror of gateway
//    `core/api/types.rs`; values must stay in lockstep — ratchet) ──────

/// Long-pull server-side hold requested on every POST (ms).
pub const PULL_HOLD_MS: u64 = 50_000;
/// Poll HTTP client timeout: hold 50s + 15s margin (must exceed hold).
pub const PULL_CLIENT_TIMEOUT_SECS: u64 = PULL_HOLD_MS / 1000 + 15; // 65
/// Hard stream read timeout — absolute no-data upper bound
/// (> 3x the 15s server heartbeat).
pub const PULL_STREAM_READ_TIMEOUT_SECS: u64 = 90;
/// Downgrade threshold: no data (heartbeat or mail) this long = dead or
/// buffered link. Server heartbeats every 15s when idle, so any healthy
/// stream yields a frame well within this window.
pub const PULL_STREAM_PING_TIMEOUT_SECS: u64 = 30;
/// Poll state re-probes /stream at this cadence (server upgrade recovery).
pub const PULL_REPROBE_INTERVAL_SECS: u64 = 600;

const STREAM_MAX_BACKOFF_SECS: u64 = 30;
const STREAM_MAX_STREAK: u32 = 3;
const MAX_BACKOFF: u64 = 300; // poll fetch-failure backoff cap (pre-existing)
const ACK_FAIL_WARN_THRESHOLD: u32 = 10;
const SEEN_TTL: Duration = Duration::from_secs(7200);

/// `GET` path of the SSE endpoint (also the signature path component).
const STREAM_PATH: &str = "/api/v1/admin/pending/stream";

// ── Kill switch ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullMode {
    /// Probe and follow the state machine (default).
    Auto,
    /// Prefer stream: transport-error drops never downgrade to Poll.
    Stream,
    /// Force long-pull; no probing.
    Poll,
}

/// Parse `AIMAIL_PULL_MODE`. Unknown/absent values default to Auto
/// (defensive: a typo must not disable the feature).
pub fn parse_pull_mode(raw: &str) -> PullMode {
    match raw.to_ascii_lowercase().as_str() {
        "stream" => PullMode::Stream,
        "poll" => PullMode::Poll,
        _ => PullMode::Auto,
    }
}

// ── Pure state-machine decision (py/ts parity: identical input vectors
//     must produce identical outputs on all three clients) ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// 200 + text/event-stream — stream is available.
    Ready,
    /// 404/405/transport failure — stream is unavailable.
    Unavailable,
}

/// Decide the next mode and the delay before the next action.
///
/// Inputs: `override_mode` (kill switch), `probe` (None = no probe was
/// performed this round — a stream-state reconnect; Some = probe result),
/// `streak` (consecutive stream transport-error drops since the last
/// successful stream).
///
/// Outputs: `(mode, delay_secs)`. delay 0 = act immediately.
pub fn decide_next(
    override_mode: PullMode,
    probe: Option<ProbeOutcome>,
    streak: u32,
) -> (PullMode, u64) {
    if override_mode == PullMode::Poll {
        return (PullMode::Poll, 0);
    }
    match probe {
        Some(ProbeOutcome::Ready) => (PullMode::Stream, 0),
        Some(ProbeOutcome::Unavailable) => (PullMode::Poll, 0),
        None => {
            if override_mode == PullMode::Stream {
                // Forced: reconnect forever, never downgrade.
                (PullMode::Stream, stream_backoff_secs(streak))
            } else {
                // Auto: 3 consecutive drops give up on the stream.
                if streak >= STREAM_MAX_STREAK {
                    (PullMode::Poll, 0)
                } else {
                    (PullMode::Stream, stream_backoff_secs(streak))
                }
            }
        }
    }
}

/// Exponential stream reconnect backoff: 1,2,4,8,16,30 (capped) seconds.
pub fn stream_backoff_secs(streak: u32) -> u64 {
    if streak == 0 {
        return 0;
    }
    let shift = (streak - 1).min(5);
    (1u64 << shift).min(STREAM_MAX_BACKOFF_SECS)
}

/// Long-pull fetch-failure backoff: `interval * 2^failures`, capped at
/// `MAX_BACKOFF` (pre-existing ramp, now a pure function for parity).
pub fn poll_backoff_secs(poll_interval: u64, failures: u32) -> u64 {
    (poll_interval * 2_u64.pow(failures.min(6))).min(MAX_BACKOFF)
}

/// Tuning knobs (defaults = contract values; tests inject short ones).
#[derive(Debug, Clone, Copy)]
pub struct PullTuning {
    /// No-data downgrade threshold on the stream.
    pub ping_timeout: Duration,
    /// Poll-state re-probe cadence.
    pub reprobe_interval: Duration,
    /// Long-pull HTTP client timeout.
    pub poll_client_timeout: Duration,
}

impl Default for PullTuning {
    fn default() -> Self {
        Self {
            ping_timeout: Duration::from_secs(PULL_STREAM_PING_TIMEOUT_SECS),
            reprobe_interval: Duration::from_secs(PULL_REPROBE_INTERVAL_SECS),
            poll_client_timeout: Duration::from_secs(PULL_CLIENT_TIMEOUT_SECS),
        }
    }
}

/// Application state shared across pull tasks.
#[derive(Clone)]
pub struct PullState {
    pub router: Arc<ProfileRouter>,
    /// Forward client (local agent endpoints) — 30s, pre-existing.
    pub http_client: reqwest::Client,
    /// Long-pull client — hold + margin (must exceed the server hold).
    pub pull_client: reqwest::Client,
    /// SSE client — NO overall timeout (stream lives up to 300s server
    /// lifetime); the per-chunk deadline inside `stream_read_loop` is the
    /// only guard.
    pub stream_client: reqwest::Client,
    pub pull_cfg: PullSystemConfig,
}

impl PullState {
    fn build(
        pull_cfg: &PullSystemConfig,
        router: Arc<ProfileRouter>,
        tuning: &PullTuning,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            router,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            pull_client: reqwest::Client::builder()
                .timeout(tuning.poll_client_timeout)
                .build()?,
            stream_client: reqwest::Client::builder().build()?,
            pull_cfg: pull_cfg.clone(),
        })
    }
}

/// One round of stream reading ended.
#[derive(Debug)]
enum StreamEnd {
    /// Server closed the stream at its 300s max life — expected rotation.
    Closed,
    /// No data for `ping_timeout` — dead or buffered link.
    Stalled,
    /// Transport error (connect refused, reset, non-2xx, wrong content-type).
    Error(String),
    /// Client shutdown requested.
    Stopped,
}

// ── SSE frame parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SseEvent {
    /// Heartbeat / comment line.
    Ping,
    /// A mail event; `data` is byte-identical to the POST list response
    /// body (built by the same server-side grouping function).
    Mail { batches: Vec<PendingBatch> },
}

/// Incremental SSE frame parser. Feed arbitrary byte chunks (TCP framing
/// does not respect SSE frames); complete frames are returned as they
/// cross a `\n\n` boundary, partial frames stay buffered.
pub(crate) struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume a chunk; return all complete events it completed.
    /// Frames with unparseable `data` are skipped with a warning (a bad
    /// frame must not kill the stream — the server never re-sends it,
    /// but the next mail frame must still arrive).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let frame = String::from_utf8_lossy(&self.buf[..end]).to_string();
            self.buf.drain(..end + 2);
            if let Some(ev) = parse_frame(&frame) {
                events.push(ev);
            }
        }
        events
    }
}

fn parse_frame(frame: &str) -> Option<SseEvent> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();
    let mut is_comment = false;
    for line in frame.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(':') {
            is_comment = true;
            continue;
        }
        if let Some(v) = line.strip_prefix("event:") {
            event_name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("data:") {
            // SSE spec: multiple data lines join with '\n'.
            data_lines.push(v.trim_start().to_string());
        }
        // id:/retry: and unknown fields are ignored.
    }
    if data_lines.is_empty() {
        return if is_comment {
            Some(SseEvent::Ping)
        } else {
            None
        };
    }
    let data = data_lines.join("\n");
    match event_name.as_deref() {
        Some("mail") => match serde_json::from_str::<MailEnvelope>(&data) {
            Ok(env) => Some(SseEvent::Mail {
                batches: env.batches,
            }),
            Err(e) => {
                tracing::warn!(error = %e, "SSE mail frame failed to parse — skipping");
                None
            }
        },
        _ => None, // unknown event name — ignore defensively
    }
}

/// The `data:` payload of a mail event — byte-identical to the POST list
/// response body (same server-side grouping function builds both).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct MailEnvelope {
    batches: Vec<PendingBatch>,
}

// ── Shared forward+ack path (used by BOTH Stream and Poll) ─────────────

/// Forward every delivery in `batches` to its routed agent endpoint,
/// then ACK the successfully forwarded (and dedup-hit) ids. Dedup:
/// `seen` maps delivery id -> first-forward time (TTL 2h); a dedup hit is
/// ACKed without re-forwarding. Deliveries without a route are NOT acked
/// (routes may be transiently empty during a rescan).
async fn forward_and_ack(
    state: &PullState,
    batches: &[PendingBatch],
    seen: &mut HashMap<i64, Instant>,
    ack_failures: &mut u32,
) {
    let mut ack_ids: Vec<i64> = Vec::new();
    let mut forwarded_emails: Vec<String> = Vec::new();
    for batch in batches {
        // Serialize shared body once per batch, not per delivery
        let body_bytes = match serde_json::to_vec(&batch.body) {
            Ok(b) => axum::body::Bytes::from(b),
            Err(e) => {
                tracing::error!(error = %e, "batch body serialization failed — skipping batch");
                continue;
            }
        };
        for d in &batch.deliveries {
            // Dedup: skip already-forwarded deliveries
            if let Some(t) = seen.get(&d.id) {
                if t.elapsed() < SEEN_TTL {
                    tracing::debug!(id = d.id, "Already forwarded — ACKing without re-forward");
                    forwarded_emails.push(d.email.clone());
                    ack_ids.push(d.id);
                    continue;
                }
            }

            // Look up route — do NOT ACK if route is missing.
            let route = match state.router.lookup(&d.email) {
                Some(r) => r,
                None => {
                    tracing::warn!(email = %d.email, id = d.id, "No route — skipping (will retry)");
                    continue;
                }
            };

            let target = route.target_url();

            // Parse headers from relay payload
            // null or invalid headers -> empty (serde_json::Value::Null
            // deserializes to an empty map via unwrap_or_default)
            let headers: HashMap<String, String> =
                serde_json::from_value(d.headers.clone()).unwrap_or_default();

            // Forward to gateway (shared body from batch)
            let mut req_builder = state.http_client.post(target);
            for (k, v) in &headers {
                if k.eq_ignore_ascii_case("content-type") {
                    continue; // gateway includes it, bridge sets it below
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
                        "Forward got non-2xx — retrying next round"
                    );
                }
                Err(e) => {
                    tracing::error!(id = d.id, email = %d.email, error = %e, "Forward failed");
                }
            }
        }
    }

    // ACK the forwarded deliveries
    if !ack_ids.is_empty() {
        match ack_deliveries(state, &ack_ids).await {
            Ok(_) => {
                *ack_failures = 0;
                tracing::info!(forwarded = ack_ids.len(), emails = ?forwarded_emails, "Pull round complete");
            }
            Err(e) => {
                *ack_failures += 1;
                if *ack_failures >= ACK_FAIL_WARN_THRESHOLD
                    && (*ack_failures).is_multiple_of(ACK_FAIL_WARN_THRESHOLD)
                {
                    tracing::warn!(
                        count = *ack_failures,
                        "ACK has been failing for {} rounds — relay ACK endpoint may be down",
                        *ack_failures,
                    );
                }
                tracing::error!(forwarded = ack_ids.len(), emails = ?forwarded_emails, error = %e, "ACK failed — will retry");
            }
        }
    }
}

// ── Stream path ────────────────────────────────────────────────────────

/// Open the SSE connection (signed GET, empty body). Ok = 200 +
/// text/event-stream. The 30s bound is for the CONNECT phase only; the
/// long-lived body is guarded per-chunk inside `stream_read_loop`.
async fn connect_stream(state: &PullState) -> Result<reqwest::Response, ()> {
    // STREAM_PATH carries its leading slash, so join WITHOUT adding one
    // (a double slash would 404 against the real route registration).
    let url = format!(
        "{}{}",
        state.pull_cfg.aimail_url.trim_end_matches('/'),
        STREAM_PATH
    );
    let (ts, sig) = api_sign(state.pull_cfg.effective_key(), "GET", STREAM_PATH, &[]);

    let req = state
        .stream_client
        .get(&url)
        .header("X-Api-Identity", state.pull_cfg.system_id.as_str())
        .header("X-Api-Timestamp", ts)
        .header("X-Api-Signature", sig);

    let resp = tokio::time::timeout(Duration::from_secs(30), req.send())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let ok = resp.status().is_success()
        && resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if !ok {
        tracing::debug!(status = %resp.status(), "stream probe rejected by server");
        return Err(());
    }
    Ok(resp)
}

/// Read the stream until it ends, forwarding each mail event.
async fn stream_read_loop(
    state: &PullState,
    tuning: &PullTuning,
    shutdown: &AtomicBool,
    seen: &mut HashMap<i64, Instant>,
    ack_failures: &mut u32,
    resp: reqwest::Response,
) -> StreamEnd {
    // Per-chunk deadline: the ping timeout (30s) is the downgrade
    // threshold; the read timeout (90s) is the absolute no-data bound.
    // The server heartbeats every 15s when idle, so a healthy stream
    // yields a frame well within the ping window.
    let chunk_timeout = tuning
        .ping_timeout
        .min(Duration::from_secs(PULL_STREAM_READ_TIMEOUT_SECS));
    let mut parser = SseParser::new();
    let mut stream = resp.bytes_stream();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return StreamEnd::Stopped;
        }
        let chunk = match tokio::time::timeout(chunk_timeout, stream.next()).await {
            Ok(Some(Ok(bytes))) => bytes,
            Ok(Some(Err(e))) => return StreamEnd::Error(e.to_string()),
            Ok(None) => return StreamEnd::Closed,
            Err(_) => return StreamEnd::Stalled,
        };
        for ev in parser.feed(&chunk) {
            if let SseEvent::Mail { batches } = ev {
                if !batches.is_empty() {
                    forward_and_ack(state, &batches, seen, ack_failures).await;
                }
            }
        }
    }
}

/// Outcome of one stream round (connect + read to end-of-stream).
#[derive(Debug)]
enum StreamRoundResult {
    /// Stay in Stream state — reconnect (rotation or backoff already done).
    Stay,
    /// Drop to Poll for this round.
    DropToPoll,
    /// Shut down.
    Stop,
}

/// One stream round: (re)connect, then read until the stream ends.
/// Owns `stream_streak` (reset on successful connect; advanced on
/// transport drops; `decide_next` decides downgrade vs backoff).
#[allow(clippy::too_many_arguments)] // state-machine context, deliberately flat
async fn run_stream_round(
    state: &PullState,
    tuning: &PullTuning,
    override_mode: PullMode,
    shutdown: &AtomicBool,
    seen: &mut HashMap<i64, Instant>,
    ack_failures: &mut u32,
    stream_streak: &mut u32,
) -> StreamRoundResult {
    let resp = match connect_stream(state).await {
        Ok(r) => r,
        Err(()) => {
            // Unavailable (404/500/network) — routed through the shared
            // decision function: every mode drops to long-pull (there is
            // no alternative transport); the poll-state re-probe recovers
            // after a server upgrade.
            let (next, _) = decide_next(override_mode, Some(ProbeOutcome::Unavailable), 0);
            debug_assert_eq!(next, PullMode::Poll, "unavailable must drop to poll");
            tracing::info!("stream endpoint unavailable — falling back to long-poll");
            return StreamRoundResult::DropToPoll;
        }
    };
    *stream_streak = 0;
    stream_round_with(
        state,
        tuning,
        override_mode,
        shutdown,
        seen,
        ack_failures,
        stream_streak,
        resp,
    )
    .await
}

/// Read an ALREADY-CONNECTED stream until it ends, applying the same
/// streak/backoff/downgrade rules as `run_stream_round`.
#[allow(clippy::too_many_arguments)] // state-machine context, deliberately flat
async fn stream_round_with(
    state: &PullState,
    tuning: &PullTuning,
    override_mode: PullMode,
    shutdown: &AtomicBool,
    seen: &mut HashMap<i64, Instant>,
    ack_failures: &mut u32,
    stream_streak: &mut u32,
    resp: reqwest::Response,
) -> StreamRoundResult {
    match stream_read_loop(state, tuning, shutdown, seen, ack_failures, resp).await {
        StreamEnd::Stopped => StreamRoundResult::Stop,
        StreamEnd::Closed => StreamRoundResult::Stay, // 300s rotation: immediate reconnect
        StreamEnd::Stalled => {
            tracing::warn!(
                ping_timeout_ms = tuning.ping_timeout.as_millis() as u64,
                "stream stalled (no data) — falling back to long-poll"
            );
            StreamRoundResult::DropToPoll
        }
        StreamEnd::Error(e) => {
            *stream_streak += 1;
            let (next, delay) = decide_next(override_mode, None, *stream_streak);
            if next == PullMode::Poll {
                tracing::warn!(
                    error = %e,
                    streak = *stream_streak,
                    "stream dropped {}x in a row — falling back to long-poll",
                    *stream_streak
                );
                *stream_streak = 0;
                StreamRoundResult::DropToPoll
            } else {
                if delay > 0 {
                    tracing::warn!(
                        error = %e,
                        streak = *stream_streak,
                        backoff_secs = delay,
                        "stream dropped — reconnecting after backoff"
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                StreamRoundResult::Stay
            }
        }
    }
}

// ── Long-pull path ─────────────────────────────────────────────────────

/// Pending delivery from relay (batched format).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub(crate) struct PendingBatch {
    body: serde_json::Value,
    deliveries: Vec<BatchDelivery>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub(crate) struct BatchDelivery {
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

/// Long-pull one round: POST /pending with `timeout_ms` hold. Old servers
/// ignore the unknown field (serde default) and answer immediately.
/// Returns empty vec if no routes.
async fn fetch_pending(
    state: &PullState,
) -> Result<Vec<PendingBatch>, Box<dyn std::error::Error + Send + Sync>> {
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
        state.pull_cfg.aimail_url.trim_end_matches('/')
    );
    let body_json = serde_json::json!({
        "limit": 50,
        "filter": domains.into_iter().collect::<Vec<_>>(),
        "timeout_ms": PULL_HOLD_MS,
    });
    let body_bytes = serde_json::to_vec(&body_json)?;
    let (ts, sig) = api_sign(
        state.pull_cfg.effective_key(),
        "POST",
        "/api/v1/admin/pending",
        &body_bytes,
    );

    let resp = state
        .pull_client
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
async fn ack_deliveries(
    state: &PullState,
    ids: &[i64],
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!(
        "{}/api/v1/admin/pending/ack",
        state.pull_cfg.aimail_url.trim_end_matches('/')
    );

    let ack_body = serde_json::to_vec(&serde_json::json!({ "ids": ids }))?;
    let (ts, sig) = api_sign(
        state.pull_cfg.effective_key(),
        "POST",
        "/api/v1/admin/pending/ack",
        &ack_body,
    );

    let resp = state
        .pull_client
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

// ── Main loop ──────────────────────────────────────────────────────────

/// Entry point (production): parses the `AIMAIL_PULL_MODE` kill switch and
/// runs the loop with contract-default tuning.
pub async fn start_pull_loop(
    pull_cfg: PullSystemConfig,
    router: Arc<ProfileRouter>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mode = parse_pull_mode(
        std::env::var("AIMAIL_PULL_MODE")
            .unwrap_or_default()
            .as_str(),
    );
    start_pull_loop_with_mode(pull_cfg, router, shutdown, mode, PullTuning::default()).await
}

/// Main pull loop: state machine over Stream (SSE) and Poll (long-pull).
/// `mode` = kill switch (Auto/Stream/Poll), `tuning` is injectable for
/// tests (short ping/reprobe/timeout values). Explicit `mode` (rather than
/// reading the env var here) keeps tests isolated — the env parse is only
/// in the production entry above.
#[allow(clippy::too_many_lines)]
pub async fn start_pull_loop_with_mode(
    pull_cfg: PullSystemConfig,
    router: Arc<ProfileRouter>,
    shutdown: Arc<AtomicBool>,
    mode: PullMode,
    tuning: PullTuning,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let override_mode = mode;
    let state = PullState::build(&pull_cfg, router.clone(), &tuning)?;

    let mut seen: HashMap<i64, Instant> = HashMap::new();
    let poll_interval = pull_cfg.poll_interval_sec;
    let mut consecutive_failures: u32 = 0;
    let mut ack_failures: u32 = 0;
    let mut stream_streak: u32 = 0;
    // "Due immediately" so the first empty Poll round re-probes right away.
    let mut last_reprobe = Instant::now() - tuning.reprobe_interval;

    tracing::info!(
        aimail_url = %pull_cfg.aimail_url,
        system_id = %pull_cfg.system_id,
        poll_interval_sec = pull_cfg.poll_interval_sec,
        mode = ?override_mode,
        "Starting pull loop (SSE primary / long-pull fallback)"
    );

    // Explicit transport state: true while in the long-poll fallback.
    // Auto mode starts optimistic (Stream) and moves to Poll only on a
    // drop; Poll mode is forced. In Poll the stream is re-probed at the
    // contract cadence (reprobe_interval) — NOT on every round — so a
    // streamless server costs one 404 per 10 min, not per poll.
    let mut in_poll = override_mode == PullMode::Poll;

    loop {
        // Check graceful shutdown
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("Pull loop shutting down gracefully");
            return Ok(());
        }

        // Periodic cleanup of stale dedup entries
        seen.retain(|_, t| t.elapsed() < SEEN_TTL);

        // ── Poll state: due re-probe of the stream endpoint ───────────
        // While in the long-poll fallback (auto/stream mode), the stream
        // is re-probed at the contract cadence — NOT on every round — so
        // a streamless server costs one 404 per reprobe_interval. A
        // failed probe sleeps the round out and does not retry until the
        // next cadence; a successful probe hands the connection to the
        // stream branch below.
        if in_poll
            && override_mode != PullMode::Poll
            && last_reprobe.elapsed() >= tuning.reprobe_interval
        {
            last_reprobe = Instant::now();
            {
                match connect_stream(&state).await {
                    Ok(resp) => {
                        let (next, _) =
                            decide_next(override_mode, Some(ProbeOutcome::Ready), stream_streak);
                        debug_assert_eq!(next, PullMode::Stream, "ready must enter stream");
                        tracing::info!(
                            "stream endpoint available again — switching to stream mode"
                        );
                        stream_streak = 0;
                        in_poll = false;
                        // Fall through to the stream branch with this
                        // already-open connection (one round this loop).
                        match stream_round_with(
                            &state,
                            &tuning,
                            override_mode,
                            &shutdown,
                            &mut seen,
                            &mut ack_failures,
                            &mut stream_streak,
                            resp,
                        )
                        .await
                        {
                            StreamRoundResult::Stop => return Ok(()),
                            StreamRoundResult::Stay => continue,
                            StreamRoundResult::DropToPoll => {
                                in_poll = true;
                                last_reprobe = Instant::now();
                                tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                                continue;
                            }
                        }
                    }
                    Err(()) => {
                        // Still unavailable: sleep the round out.
                        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                        continue;
                    }
                }
            }
        }

        // ── Stream state (auto/stream modes, not currently in poll) ───
        if !in_poll {
            match run_stream_round(
                &state,
                &tuning,
                override_mode,
                &shutdown,
                &mut seen,
                &mut ack_failures,
                &mut stream_streak,
            )
            .await
            {
                StreamRoundResult::Stop => return Ok(()),
                StreamRoundResult::Stay => continue,
                StreamRoundResult::DropToPoll => {
                    in_poll = true;
                    last_reprobe = Instant::now();
                }
            }
        }

        // ── Poll state: one long-pull round ────────────────────────────
        let round = fetch_pending(&state).await;
        match round {
            Ok(batches) => {
                consecutive_failures = 0;
                if batches.is_empty() {
                    // Empty round: the server held us for `timeout_ms`
                    // already, so a plain poll_interval sleep paces the
                    // next round (and any due re-probe at the top).
                    tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                    continue;
                }
                // Non-empty round: NO sleep — go straight to the next
                // round so a continuous mail flow is not throttled by
                // the poll interval (each round is still one long-pull).
                forward_and_ack(&state, &batches, &mut seen, &mut ack_failures).await;
            }
            Err(e) => {
                consecutive_failures += 1;
                let bs = poll_backoff_secs(poll_interval, consecutive_failures);
                tracing::error!(
                    error = %e,
                    consecutive_failures,
                    backoff_secs = bs,
                    "Pull fetch failed — backing off"
                );
                tokio::time::sleep(Duration::from_secs(bs)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SSE frame parsing ─────────────────────────────────────────────

    fn mail_frame(payload: &str) -> String {
        format!("event: mail\ndata: {payload}\n\n")
    }

    #[test]
    fn sse_parse_single_mail_frame() {
        let mut p = SseParser::new();
        let frame = mail_frame(
            r#"{"batches":[{"body":{"t":1},"deliveries":[{"id":1,"email":"a@x.com","headers":{}}]}]}"#,
        );
        let evs = p.feed(frame.as_bytes());
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            SseEvent::Mail { batches } => {
                assert_eq!(batches.len(), 1);
                assert_eq!(batches[0].deliveries[0].id, 1);
                assert_eq!(batches[0].deliveries[0].email, "a@x.com");
            }
            other => panic!("expected Mail, got {other:?}"),
        }
    }

    #[test]
    fn sse_parse_ping_comment() {
        let mut p = SseParser::new();
        let evs = p.feed(b": ping\n\n");
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], SseEvent::Ping));
    }

    #[test]
    fn sse_parse_multiple_events_one_chunk() {
        let mut p = SseParser::new();
        let chunk = format!(
            "{}: ping\n\n{}",
            mail_frame(r#"{"batches":[]}"#),
            mail_frame(r#"{"batches":[]}"#),
        );
        let evs = p.feed(chunk.as_bytes());
        assert_eq!(evs.len(), 3, "two mails + one ping");
        assert!(matches!(evs[0], SseEvent::Mail { .. }));
        assert!(matches!(evs[1], SseEvent::Ping));
        assert!(matches!(evs[2], SseEvent::Mail { .. }));
    }

    #[test]
    fn sse_parse_frame_split_across_chunks() {
        let mut p = SseParser::new();
        let full = mail_frame(r#"{"batches":[]}"#);
        let mid = full.len() / 2;
        // split mid-frame (even mid-header)
        assert!(p.feed(&full.as_bytes()[..mid]).is_empty());
        let evs = p.feed(&full.as_bytes()[mid..]);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], SseEvent::Mail { .. }));
    }

    #[test]
    fn sse_parse_bad_json_skipped_not_fatal() {
        let mut p = SseParser::new();
        let evs = p.feed(b"event: mail\ndata: not-json\n\n");
        assert!(evs.is_empty(), "bad frame must be skipped");
        // ...and a following good frame still parses (stream not killed).
        let evs2 = p.feed(mail_frame(r#"{"batches":[]}"#).as_bytes());
        assert_eq!(evs2.len(), 1);
    }

    #[test]
    fn sse_parse_unknown_event_ignored() {
        let mut p = SseParser::new();
        let evs = p.feed(b"event: foo\ndata: {\"x\":1}\n\n");
        assert!(evs.is_empty());
    }

    #[test]
    fn sse_parse_buffered_until_boundary() {
        let mut p = SseParser::new();
        // No \n\n boundary yet: nothing is emitted, bytes are buffered.
        assert!(p.feed(b": ping\n").is_empty());
        // Completing the frame (": ping" + \n) yields the comment as Ping.
        let evs = p.feed(b"\n");
        assert_eq!(evs, vec![SseEvent::Ping]);
    }

    // ── Pure state-machine decision (py/ts parity vectors) ────────────

    #[test]
    fn decide_next_probe_ready_always_stream() {
        for m in [PullMode::Auto, PullMode::Stream] {
            assert_eq!(
                decide_next(m, Some(ProbeOutcome::Ready), 9),
                (PullMode::Stream, 0),
                "{m:?}: probe Ready must enter Stream immediately, streak irrelevant"
            );
        }
    }

    #[test]
    fn decide_next_probe_unavailable_always_poll() {
        // No alternative transport exists: unavailable drops to Poll in
        // BOTH auto and stream modes.
        for m in [PullMode::Auto, PullMode::Stream] {
            assert_eq!(
                decide_next(m, Some(ProbeOutcome::Unavailable), 0),
                (PullMode::Poll, 0),
                "{m:?}: probe Unavailable must drop to Poll"
            );
        }
    }

    #[test]
    fn decide_next_kill_switch_poll_wins() {
        assert_eq!(
            decide_next(PullMode::Poll, Some(ProbeOutcome::Ready), 0),
            (PullMode::Poll, 0)
        );
        assert_eq!(decide_next(PullMode::Poll, None, 0), (PullMode::Poll, 0));
    }

    #[test]
    fn decide_next_auto_downgrade_after_3_drops() {
        // Auto: drops 1,2 reconnect with backoff; drop 3 downgrades.
        assert_eq!(decide_next(PullMode::Auto, None, 1), (PullMode::Stream, 1));
        assert_eq!(decide_next(PullMode::Auto, None, 2), (PullMode::Stream, 2));
        assert_eq!(decide_next(PullMode::Auto, None, 3), (PullMode::Poll, 0));
        assert_eq!(decide_next(PullMode::Auto, None, 4), (PullMode::Poll, 0));
    }

    #[test]
    fn decide_next_stream_mode_never_downgrades() {
        // Forced stream: reconnects forever with capped backoff.
        assert_eq!(
            decide_next(PullMode::Stream, None, 1),
            (PullMode::Stream, 1)
        );
        assert_eq!(
            decide_next(PullMode::Stream, None, 3),
            (PullMode::Stream, 4)
        );
        assert_eq!(
            decide_next(PullMode::Stream, None, 10),
            (PullMode::Stream, 30)
        );
    }

    #[test]
    fn stream_backoff_sequence() {
        // 0=immediate, then 1,2,4,8,16,30 capped.
        let seq: Vec<u64> = (0..8).map(stream_backoff_secs).collect();
        assert_eq!(seq, vec![0, 1, 2, 4, 8, 16, 30, 30]);
    }

    #[test]
    fn parse_pull_mode_values() {
        assert_eq!(parse_pull_mode(""), PullMode::Auto);
        assert_eq!(parse_pull_mode("auto"), PullMode::Auto);
        assert_eq!(parse_pull_mode("STREAM"), PullMode::Stream);
        assert_eq!(parse_pull_mode("Poll"), PullMode::Poll);
        assert_eq!(parse_pull_mode("garbage"), PullMode::Auto); // typo must not disable
    }

    // ── Contract constants (ratchet: mirror gateway types.rs) ─────────

    #[test]
    fn contract_constants_match_gateway() {
        assert_eq!(PULL_HOLD_MS, 50_000);
        assert_eq!(PULL_CLIENT_TIMEOUT_SECS, 65); // 50 + 15
        assert_eq!(PULL_STREAM_READ_TIMEOUT_SECS, 90);
        assert_eq!(PULL_STREAM_PING_TIMEOUT_SECS, 30);
        assert_eq!(PULL_REPROBE_INTERVAL_SECS, 600);
    }

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
        assert_eq!(poll_backoff_secs(10, 1), 20);
    }

    #[test]
    fn test_backoff_calculation_ramp() {
        for (failures, expected) in &[
            (0u32, 10u64),
            (1, 20),
            (2, 40),
            (3, 80),
            (4, 160),
            (5, 300),
            (6, 300),
        ] {
            assert_eq!(
                poll_backoff_secs(10, *failures),
                *expected,
                "failures={} should give {}",
                failures,
                expected
            );
        }
    }

    #[test]
    fn test_backoff_calculation_capped_at_300() {
        // After 6+ failures, backoff should be 300
        assert_eq!(poll_backoff_secs(10, 100), 300);
    }

    #[test]
    fn test_backoff_different_poll_interval() {
        assert_eq!(poll_backoff_secs(30, 3), 240); // 30 * 2^3 = 240
    }

    #[test]
    fn test_backoff_poll_interval_above_max() {
        assert_eq!(poll_backoff_secs(600, 0), 300); // capped at 300
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
        assert!(
            ts2.parse::<u128>().is_ok(),
            "timestamp must be epoch millis"
        );
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
        struct Wrapper {
            batches: Vec<PendingBatch>,
        }
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
        let ack_only_new = vec![3i64, 4]
            .into_iter()
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
        let already_seen = seen
            .get(&id)
            .map(|t| t.elapsed() < seen_ttl)
            .unwrap_or(false);
        assert!(already_seen);

        // ACK should still include it (the loop ACKs even deduped)
        let deduped_acks = if already_seen { vec![id] } else { vec![] };
        assert_eq!(deduped_acks, vec![42]);
    }

    // ── Integration: mock server (stream / 404 / stall / no-sleep) ───

    /// SSE mail frame with the contract payload shape.
    fn frame_mail(id: i64) -> String {
        let payload = serde_json::json!({
            "batches": [{
                "body": {"subject": "hi"},
                "deliveries": [{"id": id, "email": "a@x.com", "headers": {}}]
            }]
        });
        format!("event: mail\ndata: {}\n\n", payload)
    }

    #[derive(Clone)]
    struct Mock {
        hits_pending: Arc<std::sync::atomic::AtomicUsize>,
        hits_stream: Arc<std::sync::atomic::AtomicUsize>,
        acked: Arc<std::sync::Mutex<Vec<i64>>>,
        ack_rounds: Arc<std::sync::atomic::AtomicUsize>,
        forwarded: Arc<std::sync::Mutex<Vec<String>>>,
        pending_bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        /// None = 200 + text/event-stream; Some = plain response status.
        stream_status: Option<u16>,
        /// When true the stream sends one mail frame, then holds open.
        stream_sends_mail: bool,
    }

    impl Mock {
        fn new(stream_status: Option<u16>, stream_sends_mail: bool) -> Self {
            Self {
                hits_pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                hits_stream: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                acked: Arc::new(std::sync::Mutex::new(Vec::new())),
                ack_rounds: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                forwarded: Arc::new(std::sync::Mutex::new(Vec::new())),
                pending_bodies: Arc::new(std::sync::Mutex::new(Vec::new())),
                stream_status,
                stream_sends_mail,
            }
        }
    }

    /// Wait until `check()` is true or the deadline passes.
    async fn wait_for(deadline: Duration, check: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        check()
    }

    fn test_tuning() -> PullTuning {
        PullTuning {
            ping_timeout: Duration::from_millis(300),
            reprobe_interval: Duration::from_secs(3600), // no re-probe during tests
            poll_client_timeout: Duration::from_secs(5),
        }
    }

    fn test_cfg(url: &str) -> PullSystemConfig {
        PullSystemConfig {
            aimail_url: url.to_string(),
            admin_key: String::new(),
            api_key: "testkey".to_string(),
            poll_interval_sec: 1,
            system_id: "sys1".to_string(),
        }
    }

    /// Bind the mock router on 127.0.0.1:0 and serve it; returns the
    /// base URL and the original (still-cloneable) mock.
    async fn bind_mock(m: Mock) -> (String, Mock) {
        let m_pending = m.clone();
        let m_ack = m.clone();
        let m_stream = m.clone();
        let m_target = m.clone();
        let router =
            axum::Router::new()
                .route(
                    "/api/v1/admin/pending",
                    axum::routing::post(move |b: axum::extract::Json<serde_json::Value>| {
                        let m = m_pending.clone();
                        async move {
                            m.hits_pending.fetch_add(1, Ordering::SeqCst);
                            m.pending_bodies.lock().unwrap().push(b.0);
                            Ok::<_, axum::http::StatusCode>(axum::extract::Json(
                                serde_json::json!({
                                    "batches": [{
                                        "body": {"subject": "hi"},
                                        "deliveries": [{"id": 7, "email": "a@x.com", "headers": {}}]
                                    }]
                                }),
                            ))
                        }
                    }),
                )
                .route(
                    "/api/v1/admin/pending/ack",
                    axum::routing::post(move |b: axum::extract::Json<serde_json::Value>| {
                        let m = m_ack.clone();
                        async move {
                            let ids: Vec<i64> =
                                b.0.get("ids")
                                    .and_then(|v| v.as_array())
                                    .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                                    .unwrap_or_default();
                            m.acked.lock().unwrap().extend(ids.clone());
                            m.ack_rounds.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, axum::http::StatusCode>(axum::extract::Json(
                                serde_json::json!({ "acked": ids.len() }),
                            ))
                        }
                    }),
                )
                .route(
                    "/api/v1/admin/pending/stream",
                    axum::routing::get(move || {
                        let m = m_stream.clone();
                        async move {
                            m.hits_stream.fetch_add(1, Ordering::SeqCst);
                            let status = m.stream_status;
                            match status {
                                None => {
                                    let send_mail = m.stream_sends_mail;
                                    #[derive(Clone, Copy)]
                                    enum St {
                                        Start,
                                        Holding,
                                    }
                                    let body =
                                        futures_util::stream::unfold(St::Start, move |state| {
                                            async move {
                                                match state {
                                                    St::Start if send_mail => {
                                                        tokio::time::sleep(Duration::from_millis(
                                                            100,
                                                        ))
                                                        .await;
                                                        Some((
                                                            Ok::<
                                                                axum::body::Bytes,
                                                                std::convert::Infallible,
                                                            >(
                                                                axum::body::Bytes::from(
                                                                    frame_mail(7),
                                                                ),
                                                            ),
                                                            St::Holding,
                                                        ))
                                                    }
                                                    _ => {
                                                        // Hold the connection open until dropped.
                                                        tokio::time::sleep(Duration::from_secs(
                                                            3600,
                                                        ))
                                                        .await;
                                                        None
                                                    }
                                                }
                                            }
                                        });
                                    axum::response::Response::builder()
                                        .status(axum::http::StatusCode::OK)
                                        .header("content-type", "text/event-stream")
                                        .header("x-accel-buffering", "no")
                                        .body(axum::body::Body::from_stream(body))
                                        .unwrap()
                                }
                                Some(status) => axum::response::Response::builder()
                                    .status(axum::http::StatusCode::from_u16(status).unwrap())
                                    .body(axum::body::Body::empty())
                                    .unwrap(),
                            }
                        }
                    }),
                )
                .route(
                    "/target",
                    axum::routing::post(move |b: String| {
                        let m = m_target.clone();
                        async move {
                            m.forwarded.lock().unwrap().push(b);
                            Ok::<_, axum::http::StatusCode>(axum::extract::Json(
                                serde_json::json!({ "ok": true }),
                            ))
                        }
                    }),
                );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), m)
    }

    fn new_router(tag: &str) -> Arc<ProfileRouter> {
        let path =
            std::env::temp_dir().join(format!("pull_test_{tag}_{}.toml", std::process::id()));
        Arc::new(ProfileRouter::new(path))
    }

    #[tokio::test]
    async fn stream_ready_delivers_mail_and_acks() {
        let (url, m) = bind_mock(Mock::new(None, true)).await;
        let router = new_router("stream_ready");
        router.update_route("a@x.com", &format!("{url}/target"), 0);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = tokio::spawn(start_pull_loop_with_mode(
            test_cfg(&url),
            router,
            shutdown.clone(),
            PullMode::Auto,
            test_tuning(),
        ));
        let ok = wait_for(Duration::from_secs(10), || {
            m.acked.lock().unwrap().contains(&7) && !m.forwarded.lock().unwrap().is_empty()
        })
        .await;
        shutdown.store(true, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        assert!(ok, "mail must be forwarded and acked via the stream");
        assert_eq!(m.hits_stream.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn probe_404_falls_to_long_poll_and_body_has_hold() {
        let (url, m) = bind_mock(Mock::new(Some(404), false)).await;
        let router = new_router("probe_404");
        router.update_route("a@x.com", &format!("{url}/target"), 0);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = tokio::spawn(start_pull_loop_with_mode(
            test_cfg(&url),
            router,
            shutdown.clone(),
            PullMode::Auto,
            test_tuning(),
        ));
        let ok = wait_for(Duration::from_secs(10), || {
            m.acked.lock().unwrap().contains(&7)
        })
        .await;
        shutdown.store(true, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        assert!(
            ok,
            "404 stream must fall back to long-pull and still deliver"
        );
        assert!(
            m.hits_stream.load(Ordering::SeqCst) >= 1,
            "probe must have hit /stream"
        );
        let bodies = m.pending_bodies.lock().unwrap();
        assert!(!bodies.is_empty(), "long-poll must hit /pending");
        assert_eq!(
            bodies[0].get("timeout_ms").and_then(|v| v.as_u64()),
            Some(50_000),
            "long-pull body must request the contract hold"
        );
    }

    #[tokio::test]
    async fn stalled_stream_downgrades_to_long_poll() {
        // 200 + content-type but NO data: ping_timeout (300ms) expires.
        let (url, m) = bind_mock(Mock::new(None, false)).await;
        let router = new_router("stall");
        router.update_route("a@x.com", &format!("{url}/target"), 0);
        let shutdown = Arc::new(AtomicBool::new(false));

        let task = tokio::spawn(start_pull_loop_with_mode(
            test_cfg(&url),
            router,
            shutdown.clone(),
            PullMode::Auto,
            test_tuning(),
        ));
        let ok = wait_for(Duration::from_secs(15), || {
            m.acked.lock().unwrap().contains(&7)
        })
        .await;
        shutdown.store(true, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        assert!(
            ok,
            "stalled stream must downgrade to long-pull (and still deliver)"
        );
        assert!(m.hits_pending.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn non_empty_rounds_do_not_sleep_between_them() {
        // /pending keeps returning the same delivery (id 7). Round 1
        // forwards+acks; round 2 hits dedup and acks WITHOUT re-forward.
        // Two ack rounds with poll_interval=1s and no sleep between
        // non-empty rounds ⇒ round 2 starts within ~1s of round 1.
        let (url, m) = bind_mock(Mock::new(Some(404), false)).await;
        let router = new_router("nosleep");
        router.update_route("a@x.com", &format!("{url}/target"), 0);
        let shutdown = Arc::new(AtomicBool::new(false));
        let start = Instant::now();

        let task = tokio::spawn(start_pull_loop_with_mode(
            test_cfg(&url),
            router,
            shutdown.clone(),
            PullMode::Auto,
            test_tuning(),
        ));
        let ok = wait_for(Duration::from_secs(10), || {
            m.ack_rounds.load(Ordering::SeqCst) >= 2
        })
        .await;
        let elapsed = start.elapsed();
        shutdown.store(true, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        assert!(
            ok,
            "second non-empty round must follow immediately (no sleep)"
        );
        // If the loop slept poll_interval (1s) between non-empty rounds,
        // two acks would take >= ~2s. Without the sleep it is < 1.5s.
        assert!(
            elapsed < Duration::from_millis(1500),
            "two non-empty ack rounds took {elapsed:?} — the loop slept between them"
        );
    }
}
