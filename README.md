# aimail-bridge

[🇨🇳 中文](README_zh.md)

> Zero ports, email inbound. One port, instant forwarding to all agents.

A high-performance transparent bridge between [aimail-gateway](https://github.com/metercai/aimail-gateway)
and [Hermes agent](https://github.com/nousresearch/hermes-agent) gateway webhook endpoints.
Solves firewall penetration for heterogeneous multi-agent deployments with minimal
surface area.

---

## Why bridge

**Pain 1 — Multi-agent firewall penetration**: Each Hermes agent's webhook
runs on its own port (8645, 8646, …). Exposing them directly means N ports, N firewall
rules. Bridge's push mode provides a **single entry port** with auto-routing to every
webhook — open just one port, all agents instantly reachable.

**Pain 2 — Zero-dependency email inbound**: No public IP? No port forwarding? Pull mode
uses a single **outbound HTTP long-poll** — bridge actively fetches deliveries from
the gateway and fans out to local webhook ports. **Zero inbound ports, zero
listen sockets**, complete NAT/firewall bypass.

---

## Key features

### Secure transparent pass-through

Bridge holds zero HMAC secrets. Gateway signs with each agent's webhook secret →
bridge forwards headers & body verbatim → agent verifies. Security boundary
unchanged. Push mode supports IP allowlist + blacklist + per-IP rate limiting;
pull mode uses ACK-based consumption with 2-hour dedup cache — zero message loss,
zero duplicates.

### Lightweight, pure Rust, zero OpenSSL

Single binary ~8 MB (stripped, fat LTO). < 10 MB memory at idle, near-zero CPU.
Pure Rust TLS stack — rustls with ring crypto. Zero OpenSSL, zero native-tls,
zero system dependency beyond libc. `--daemon` double-fork daemon mode with
PID file and log file. SIGINT/SIGTERM graceful drain.

### Efficient aggregated forwarding

When one email reaches multiple recipients behind the same bridge, the gateway
sends a **single body copy** with per-recipient headers — bridge fans out to
each webhook port. Batch body serialized once, reused across all entries.
Works for both push and pull modes.


### Security hardening

- **IP allowlist + blacklist** — push mode accepts POSTs only from trusted source IPs
- **Per-IP rate limiting** — configurable req/sec cap with sliding window (default 30)
- **Body size limit** — configurable cap (default 20 MB) prevents memory exhaustion
- **Header filtering** — only business headers forwarded (`x-aimail-email`,
  `x-aimail-timestamp`, `x-webhook-signature`, `content-type`)
- **Graceful shutdown** — SIGINT/SIGTERM drain in-flight requests
- **Connection pooling** — reqwest client reused across all forwards (keep-alive)

### Zero-config automation

- **API route registration** — agents register their webhook via `POST /api/v1/routes`
- **inotify hot-reload** — changes to `aimail_routes.toml` are applied immediately
- **ACME auto-TLS** — set `hostname` → automatic Let's Encrypt certificate
  (HTTP-01 challenge), cached and auto-renewed every ~60 days
- **Dual-port mode** — `bind` port 80 + `hostname` set → auto 80→443 redirect
- **Daemon mode** — `--daemon` double-fork, PID file, log file, zero supervision

---

## Two modes

### Push — one port, instant forwarding to all agents

```
                       ┌─────────────────────────────────┐
                       │         aimail-bridge             │
                       │  (single public port 38080)       │
gateway ──POST──►      │                                  │
  alice@...+bob@...    │  alice → 127.0.0.1:8645          │──► webhook:8645
  (one body copy)      │  bob   → 127.0.0.1:8646          │──► webhook:8646
                       │  carol → 127.0.0.1:8647          │──► webhook:8647
                       └─────────────────────────────────┘
```

- Gateway POSTs to a **single port** on bridge; bridge auto-routes by agent email
- Multiple recipients → gateway sends **one body copy** (batch aggregation)
- TLS via rustls; automatic Let's Encrypt certificate when `hostname` is set
- Dual-port mode: `bind = "0.0.0.0:80"` + `hostname = "bridge.example.com"` → auto 80→443
- Real-time: gateway gets immediate HTTP response from agent via bridge

### Pull — zero ports, email inbound through NAT

```
gateway (public)                              behind NAT/firewall
  │                                               │
  │◄── POST /api/v1/admin/pending (poll every 10s) ────────────│ bridge (outbound only)
  │                                               │
  │── batches [{body, deliveries}] ──────────────►│
  │                                               │
  │                                 ┌─────────────▼──────────────────────┐
  │                                 │ fan-out to each agent webhook       │
  │                                 │ ACK forwarded deliveries            │
  │                                 └────────────────────────────────────┘
  │◄── POST /api/v1/admin/pending/ack ─────────────────────────│
```

- Single **outbound HTTP connection** to gateway, fully bypasses NAT/firewall
- **No public ports** — loopback admin API only, no inbound traffic at all
- Same batch aggregation: one body copy serialized once, reused for all recipients
- ACK-based consumption + 2-hour dedup cache — no messages lost, no duplicates
- Exponential backoff on fetch failures (max 5 minutes)

---

## Quickstart

```bash
git clone https://github.com/metercai/aimail-bridge
cd aimail-bridge
cargo build --release

# Push mode (single port, all agents)
cat > aimail_bridge.toml << 'EOF'
mode = "push"
bind = "0.0.0.0:38080"
hostname = "bridge.example.com"     # enables TLS + ACME auto-cert
admin_allowed_ips = ["127.0.0.1", "::1"]

[logging]
level = "info"       # stdout (default is /var/log/aimail-bridge.log without [logging]; non-root fails)

[push]
allowed_ips = ["10.0.0.0/8"]
EOF

# Pull mode (zero ports, outbound only)
cat > aimail_bridge.toml << 'EOF'
mode = "pull"
bind = "127.0.0.1:38080"

[logging]
level = "info"       # stdout (default is /var/log/aimail-bridge.log without [logging]; non-root fails)

[pull]
aimail_url = "http://gateway.example.com:38080"
admin_key = "sk-xxxxxxxx"           # system-scope key (pending filtered by key's system)
system_id = "admin"
EOF

# Run
./target/release/aimail-bridge

# Or daemonize
./target/release/aimail-bridge --daemon

# Check health
curl http://localhost:38080/health
# {"status":"ok","uptime_secs":42,"version":"0.7.2"}
```

---

## Configuration

### Push

```toml
mode = "push"

bind = "0.0.0.0:38080"                # listen address (default: "0.0.0.0:38080")
hostname = "bridge.example.com"       # public domain — enables TLS (see below)
admin_allowed_ips = ["127.0.0.1", "::1"]   # admin API whitelist (default: localhost)

# TLS: three ways — pick one
# 1) hostname + nothing        → ACME auto-cert (Let's Encrypt HTTP-01)
# 2) hostname + static certs   → use tls_cert / tls_key below
# 3) no hostname / IP hostname → plain HTTP
# tls_cert = "/etc/ssl/bridge.crt"   # static TLS cert (optional)
# tls_key  = "/etc/ssl/bridge.key"   # static TLS key (optional)
# acme_email = "admin@example.com"   # ACME contact (optional)
# acme_cache = "~/.acme_cache"       # ACME cache dir (default: ~/.acme_cache)

[push]
blacklist_ips = ["1.2.3.4"]          # permanently blocked IPs (default: [])
allowed_ips = ["10.0.0.0/8"]         # IP allowlist, empty = allow all (default: [])
rate_limit = 30                       # req/sec per source IP, 0 = disabled (default: 30)
body_limit_mb = 20                    # max request body in MB (default: 20)
```

### Pull

```toml
mode = "pull"

bind = "127.0.0.1:38080"              # listen address (admin API only)

[pull]
aimail_url = "http://gateway.example.com:38080"
admin_key = "sk-xxxxxxxx"            # system-scope key — must belong to the same
                                     # system as the pending deliveries
system_id = "admin"                  # system ID for pending query (default: "admin")
poll_interval_sec = 10               # poll interval in seconds (default: 10)
```

### Logging

```toml
[logging]
level = "info"                        # log level (default: "info")
file = "/var/log/aimail-bridge.log"   # log file, stdout if unset (default: none)
```



### Environment variables

| Variable | Equivalent config |
|---|---|
| `AIMAIL_BRIDGE_MODE` | `mode` |
| `AIMAIL_BRIDGE_HOSTNAME` | `hostname` (top-level) |
| `AIMAIL_GATEWAY_URL` | `pull.aimail_url` |
| `AIMAIL_BRIDGE_ADMIN_KEY` | `pull.admin_key` |
| `AIMAIL_BRIDGE_SYSTEM_ID` | `pull.system_id` |
| `AIMAIL_BRIDGE_POLL_SECS` | `pull.poll_interval_sec` |
| `AIMAIL_BRIDGE_ALLOWED_IPS` | `push.allowed_ips` (comma-separated) |
| `RUST_LOG` | tracing filter (overrides `logging.level`) |

hermes_home (config field, default `~/.hermes`)

---

## TLS & ACME

Set `hostname` in config for automatic TLS via Let's Encrypt (HTTP-01 challenge).
Certificate is cached and auto-renewed. Port 80 must be reachable for ACME validation.

**Dual-port mode:** When `bind` is port 80 + `hostname` set, port 80 handles ACME
challenge + redirects to 443; port 443 serves the application.

---

## Network scenarios

| Scenario | Mode | Notes |
|---|---|---|
| gateway + agents on same machine | Push | Bridge proxies single port to local webhook ports |
| gateway public, agents behind NAT | Pull | Bridge polls gateway outbound, zero inbound ports |
| Bridge on public VPS | Push + TLS | `hostname = "bridge.example.com"`, ACME auto-cert, dual-port |


---

