[English](README.md) | 🇨🇳 中文

# aimail-bridge

> 零端口，邮件入站。一个端口，即时透传所有 agent。

连接 [aimail-gateway](https://github.com/metercai/aimail-gateway) 和
[Hermes agent](https://github.com/nousresearch/hermes-agent) webhook 端点的
高性能透明桥接。以最小攻击面解决异构多 agent 部署的防火墙穿透问题。

---

## 为什么需要 bridge

**痛点 1 — 多 agent 防火墙穿透**：每个 Hermes agent 的 webhook 跑在各自的端口上
（8645, 8646, …），直接暴露意味着 N 个端口、N 条防火墙规则。bridge 的 push
模式提供一个**单一入口端口**，自动路由到所有 webhook —— 只开一个端口，所有
agent 即时可达。

**痛点 2 — 零依赖邮件入站**：没有公网 IP？没有端口映射？pull 模式只需要一条**出站
HTTP 长轮询**连接 —— bridge 主动从 gateway 拉取投递并扇出到本地各 webhook 端口。
**零入站端口、零监听 socket**，完全穿透 NAT/防火墙。

---

## 核心特性

### 安全的透明透传

bridge 不持有任何 HMAC 密钥。gateway 用各 agent 的 webhook secret 签名 → bridge
原样转发 headers + body → agent 验签。安全边界不变。push 模式支持 IP 白名单 + 
黑名单 + 每 IP 限速；pull 模式基于 ACK 消费 + 2 小时去重缓存，零消息丢失、
零重复投递。

### 轻量纯 Rust，零 OpenSSL

单二进制约 8 MB（stripped, fat LTO）。空闲时内存 < 10 MB，CPU 近乎为零。纯 Rust
TLS 栈 —— rustls + ring crypto。零 OpenSSL，零 native-tls，零系统依赖（仅 libc）。
SIGINT/SIGTERM 优雅排空。

### 高效的聚合转发

同一封邮件多个收件人在同一 bridge 后方时，gateway→bridge 只传**一份 body** +
每人各自的 headers，bridge 再扇出到各 webhook 端口。batch body 只序列化一次，
所有条目复用。推拉模式均支持。



### 安全加固

- **IP 白名单 + 黑名单** — push 模式仅接受受信来源 IP 的 POST
- **每 IP 限速** — 可配置 rps 上限，滑动窗口算法（默认 30）
- **Body 大小限制** — 可配置上限（默认 20 MB），防止内存耗尽
- **Header 过滤** — 只转发业务 header（`x-aimail-email`、`x-aimail-timestamp`、
  `x-webhook-signature`、`content-type`）
- **优雅关闭** — SIGINT/SIGTERM 排空进行中请求
- **连接池复用** — reqwest client 全局复用，keep-alive 长连接
- **HSTS 仅 TLS 启用** — 纯 HTTP 不发送 HSTS（RFC 6797 要求浏览器忽略）

### 零配置自动化

- **API 路由注册** — Agent 通过 `POST /api/v1/routes` 注册 webhook
- **inotify 热更新** — 修改 `aimail_routes.toml` 即时生效
- **ACME 自动 TLS** — 设置 `hostname` → 自动 Let's Encrypt 证书（HTTP-01 挑战），
  缓存复用，每 ~60 天自动续期
- **双端口模式** — `addr` 端口 80 + `hostname` 已设 → 自动 80→443 重定向
- **守护模式** — `--daemon` 双 fork，PID 文件、日志文件，无需看管

---

## 两种模式

### Push — 一个端口，即时转发所有 agent

```
                       ┌─────────────────────────────────┐
                       │         aimail-bridge             │
                       │  (单一公网端口 38080)              │
gateway ──POST──►      │                                  │
  alice@...+bob@...    │  alice → 127.0.0.1:8645          │──► webhook:8645
  (同一份 body)         │  bob   → 127.0.0.1:8646          │──► webhook:8646
                       │  carol → 127.0.0.1:8647          │──► webhook:8647
                       └─────────────────────────────────┘
```

- gateway 发到 bridge 的**单一端口**，bridge 按 agent 邮箱自动路由
- 同一封邮件多个收件人 → gateway 只传**一份 body**（批量聚合）
- TLS 由 rustls 提供；设 `hostname` 即可启用 ACME 自动证书
- 双端口：`addr = "0.0.0.0:80"` + `hostname` → 自动 80→443
- 实时性：gateway 通过 bridge 即时获取 agent HTTP 响应

### Pull — 零端口，穿透 NAT 入站

```
gateway (公网)                              NAT/防火墙内
  │                                          │
  │◄── POST /pending (poll 每 10s) ──────────│ bridge (出站，无需开放端口)
  │                                          │
  │── batches [{body, deliveries}] ─────────►│
  │                                          │
  │                            ┌─────────────▼─────────────────┐
  │                            │ fan-out 到各 agent webhook      │
  │                            │ ACK 已转发的 delivery           │
  │                            └───────────────────────────────┘
  │◄── POST /pending/ack ───────────────────│
```

- 只需要**一条出站 HTTP 连接**到 gateway，完全穿透 NAT/防火墙
- **零监听 socket**——不开放任何端口，不接收任何入站流量
- 同样支持批量聚合：body 序列化一次，所有收件人复用
- ACK 消费 + 2 小时去重缓存，不丢消息、不重复投递
- 拉取失败指数退避重启（最大 5 分钟）

---

## 快速开始

```bash
git clone https://github.com/metercai/aimail-bridge
cd aimail-bridge
cargo build --release

# Push 模式（一个端口，所有 agent）
cat > aimail_bridge.toml << 'EOF'
mode = "push"
[push]
addr = "0.0.0.0:38080"
hostname = "bridge.example.com"     # 启用 TLS + ACME 自动证书
allowed_ips = ["10.0.0.0/8"]
EOF

# Pull 模式（零端口，纯出站）
cat > aimail_bridge.toml << 'EOF'
mode = "pull"
[pull]
aimail_url = "http://gateway.example.com:38080"
admin_key = "sk-xxxxxxxx"
system_id = "admin"
EOF

# 运行
./target/release/aimail-bridge

# 或守护模式
./target/release/aimail-bridge --daemon

# 检查健康状态
curl http://localhost:38080/health
# {"status":"ok","uptime_secs":42,"version":"0.3.0"}
```

---

## 配置参考

### Push

```toml
mode = "push"

[push]
addr = "0.0.0.0:38080"                # 监听地址（默认："0.0.0.0:38080"）
hostname = "bridge.example.com"       # 启用 TLS + ACME 自动证书
# tls_cert = "/etc/ssl/bridge.crt"   # 静态 TLS 证书（可选）
# tls_key  = "/etc/ssl/bridge.key"   # 静态 TLS 私钥（可选）
# acme_cache = "./acme_cache"        # ACME 缓存目录（默认：./acme_cache）
blacklist_ips = ["1.2.3.4"]          # 永久封禁 IP（默认：[]）
allowed_ips = ["10.0.0.0/8"]         # IP 白名单，空 = 全部放行（默认：[]）
rate_limit = 30                       # 每源 IP req/sec，0 = 禁用（默认：30）
body_limit_mb = 20                    # 请求体最大 MB（默认：20）
```

### Pull

```toml
mode = "pull"

[pull]
aimail_url = "http://gateway.example.com:38080"
admin_key = "sk-xxxxxxxx"            # gateway 的 system admin API key
system_id = "admin"                  # pending 查询用的系统 ID（默认："admin"）
poll_interval_sec = 10               # 轮询间隔秒（默认：10）
```

### 日志

```toml
[logging]
level = "info"                        # 日志级别（默认："info"）
file = "/var/log/aimail-bridge.log"   # 日志文件路径，不设则 stdout
```



### 环境变量

| 变量 | 对应配置 |
|---|---|
| `AIMAIL_BRIDGE_MODE` | `mode` |
| `AIMAIL_BRIDGE_HOSTNAME` | `push.hostname` |
| `AIMAIL_GATEWAY_URL` | `pull.aimail_url` |
| `AIMAIL_BRIDGE_ADMIN_KEY` | `pull.admin_key` |
| `AIMAIL_BRIDGE_SYSTEM_ID` | `pull.system_id` |
| `AIMAIL_BRIDGE_POLL_SECS` | `pull.poll_interval_sec` |
| `AIMAIL_BRIDGE_ALLOWED_IPS` | `push.allowed_ips`（逗号分隔） |
| `HERMES_HOME` | Hermes 根目录（默认 `~/.hermes`） |
| `RUST_LOG` | tracing 过滤器（覆盖 `logging.level`） |

---

## TLS 与 ACME

设置 `hostname` 即可自动启用 Let's Encrypt TLS（HTTP-01 挑战）。
证书自动缓存续期，端口 80 需公网可达。

**双端口模式：** `addr` 为 80 + `hostname` 已设时，80 处理 ACME 验证 +
重定向到 443，443 处理 HTTPS 应用。

---

## 网络场景

| 场景 | 模式 | 说明 |
|---|---|---|
| gateway+agent 同机 | Push | bridge 单端口转发到本地各 webhook 端口 |
| gateway 在公网，agent 在 NAT 后 | Pull | bridge 出站轮询 gateway，零入站端口 |
| 公网 VPS 部署 bridge | Push + TLS | `hostname = "bridge.example.com"`，ACME 自动证书，双端口 |

---

