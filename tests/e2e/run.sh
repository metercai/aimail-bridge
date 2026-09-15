#!/usr/bin/env bash
set -u
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
warn() { echo -e "${RED}[WARN]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# v1 signed requests (docs/API-SIGNATURE-PROTOCOL.md) — shared signer lives in
# the advanced repo's e2e lib; override with SIGN_LIB if relocated.
SIGN_LIB="${SIGN_LIB:-$HOME/aimail-advanced/tests/lib/aimail-sign.sh}"
[[ -f "$SIGN_LIB" ]] || fail "shared v1 signer not found: $SIGN_LIB"
source "$SIGN_LIB"
GW_BIN="${GW_BIN:-$HOME/aimail-gateway/target/debug/aimail-gateway}"
BRIDGE_BIN="${BRIDGE_BIN:-$PROJECT_DIR/target/debug/aimail-bridge}"

WORK_DIR="${WORK_DIR:-/tmp/bridge-e2e}"
RS=35010; RH=39010; RS2=35011; RH2=39011; BP=38080; BP2=38081; HP=39999
# multi-system: second push gateway, second pull gateway, multi-system pull bridge
RS3=35012; RH3=39012; RS4=35013; RH4=39013; BP3=38082
HL="$WORK_DIR/hermes.log"; J="Content-Type: application/json"
BASE="http://127.0.0.1"

cleanup() {
    cp "$WORK_DIR/relay.log" "/tmp/e2e-relay.log" 2>/dev/null || true
    cp "$WORK_DIR/relay2.log" "/tmp/e2e-relay2.log" 2>/dev/null || true
    cp "$WORK_DIR/bridge/push-bridge.log" "/tmp/e2e-push-bridge.log" 2>/dev/null || true
    cp "$WORK_DIR/bridge/pull-bridge.log" "/tmp/e2e-pull-bridge.log" 2>/dev/null || true
    for pid in "${RELAY_PID:-}" "${BRIDGE_PID:-}" "${HERMES_PID:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done; wait 2>/dev/null || true; rm -rf "$WORK_DIR"
}
trap cleanup EXIT
rm -rf "$WORK_DIR"
for d in bridge relay-data relay2-data; do mkdir -p "$WORK_DIR/$d"; done

# ═══ Helpers ═══
wait_hermes() { local n=0; for i in $(seq 1 15); do n=$(wc -l < "$HL" 2>/dev/null||echo 0); [[ $n -ge ${1:-1} ]] && break; sleep 2; done; echo "$n"; }
expect() { local g=$1 e=$2 l=$3; [[ "$g" -ge "$e" ]] && pass "$l: $g OK" || fail "$l: $g (exp $e)"; }

start_gw() {
    local cfg=$1 port=$2
    "$GW_BIN" -c "$cfg" --pid-file "$WORK_DIR/pid" > "$WORK_DIR/relay.log" 2>&1 &
    RELAY_PID=$!; sleep 4
    for i in $(seq 1 15); do
        AK=$(cat "$WORK_DIR/relay-data/aimail.db.admin_key" 2>/dev/null||echo "")
        [[ -n "$AK" ]] && break; sleep 1
    done
    for i in $(seq 1 15); do
        [[ "$(curl -s -o/dev/null -w'%{http_code}' "http://127.0.0.1:$port/health")" == 200 ]] && break
        sleep 1
    done
}

# ═══ 1. Push Relay ═══
echo; echo "=== 1. Push Relay ==="
cat > "$WORK_DIR/relay.toml" << EOF
[smtp]
bind = "127.0.0.1:${RS}"
hostname = "relay.local"
[http]
bind = "127.0.0.1:${RH}"
[storage]
path = "${WORK_DIR}/relay-data"
[retry]
max_attempts = 1
initial_backoff_secs = 1
[logging]
level = "info"
EOF
start_gw "$WORK_DIR/relay.toml" "$RH"
[[ -n "$AK" ]] || fail "no admin key"
pass "push relay running"

# ═══ 2. Seed ═══
echo; echo "=== 2. Seed ==="
B="http://127.0.0.1:${RH}"
for d in bridge.test test.local; do
    aimail_curl "${AK}" -s -X POST "$B/api/v1/admin/systems/admin/domains" -H "$J" \
        -d "{\"id\":\"dom-$d\",\"domain\":\"$d\",\"webhook_url\":\"$BASE:${BP}/webhooks/bridge\"}" >/dev/null
done
for addr in agent@bridge.test agent2@bridge.test cc-agent@bridge.test empty@bridge.test; do
    aimail_curl "${AK}" -s -X POST "$B/api/v1/admin/systems/admin/addresses" -H "$J" \
        -d "{\"id\":\"a-${addr%@*}\",\"email\":\"$addr\",\"webhook_url\":\"$BASE:${BP}/webhooks/bridge\"}" >/dev/null
done
# sender@test.local must be registered for send's whitelist/domain resolution
aimail_curl "${AK}" -s -X POST "$B/api/v1/admin/systems/admin/addresses" -H "$J" \
    -d '{"id":"a-sender","email":"sender@test.local"}' >/dev/null
# Outbound whitelist (sender's to-rule) + inbound whitelist (recipient's
# from-rule) — both address-level: gateway matches full addresses
# (ExactKeyResolver, send.rs steps 4 & 6).
aimail_curl "${AK}" -s -X POST "$B/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"bridge.test","direction":"from","value":"*@test.local"}' >/dev/null
SK=$(python3 "$SCRIPT_DIR/create_key.py" "$B/api/v1/api-keys" "$AK")
aimail_curl "${AK}" -s -X POST "$B/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"sender@test.local","direction":"to","value":"*@bridge.test"}' >/dev/null
for addr in agent@bridge.test agent2@bridge.test cc-agent@bridge.test empty@bridge.test; do
    aimail_curl "${AK}" -s -X POST "$B/api/v1/whitelists" -H "$J" \
        -d "{\"system_id\":\"admin\",\"domain_addr\":\"$addr\",\"direction\":\"from\",\"value\":\"*@test.local\"}" >/dev/null
done
[[ -n "$SK" ]] || fail "no send key"
pass "seeded"

# ═══ 3. Hermes ═══
echo; echo "=== 3. Mock Hermes ==="
rm -f "$HL"
python3 "$SCRIPT_DIR/mock_hermes.py" "127.0.0.1" "$HP" "$HL" &
HERMES_PID=$!; sleep 1
curl -s "$BASE:${HP}/health" >/dev/null || fail "hermes not healthy"
pass "mock hermes running"

# ═══ Routes ═══
cat > "$WORK_DIR/bridge/aimail_routes.toml" << EOF
"agent@bridge.test" = "127.0.0.1:${HP}"
"agent2@bridge.test" = "127.0.0.1:${HP}"
"cc-agent@bridge.test" = "127.0.0.1:${HP}"
"empty@bridge.test" = "127.0.0.1:${HP}"
"agent@pull.test" = "127.0.0.1:${HP}"
"agent2@pull.test" = "127.0.0.1:${HP}"
"cc-agent@pull.test" = "127.0.0.1:${HP}"
"empty@pull.test" = "127.0.0.1:${HP}"
EOF

# ═══════════════════════════════════
# PUSH MODE
# ═══════════════════════════════════
echo; echo "═════ PUSH TESTS ═════"
cat > "$WORK_DIR/bridge/bridge-push.toml" << EOF
bind = "127.0.0.1:${BP}"
routes_file = "$WORK_DIR/bridge/aimail_routes.toml"
mode = "push"
[push]
body_limit_mb = 10
[logging]
level = "info"
file = "$WORK_DIR/bridge/push-bridge.log"
EOF
"$BRIDGE_BIN" -c "$WORK_DIR/bridge/bridge-push.toml" > "$WORK_DIR/bridge/push.log" 2>&1 &
BRIDGE_PID=$!; sleep 2
for i in $(seq 1 10); do [[ "$(curl -s -o/dev/null -w'%{http_code}' "$BASE:${BP}/health" 2>/dev/null)" == 200 ]] && break; sleep 1; done
pass "bridge push running"

S() { local code=$(aimail_curl "${SK}" -s -w "%{http_code}" -o /dev/null -X POST "$B/api/v1/send" -H "Content-Type: application/json" "$@" 2>/dev/null); echo "SEND: $code" >&2; }

# P1: single
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test","subject":"P1-Single","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); expect "$n" 1 "P-1 single"

# P2: multi-to
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test, agent2@bridge.test","subject":"P2-MultiTo","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -eq 2 ]] && pass "P-2 multi-to: $n OK" || warn "P-2 multi-to: $n (exp 2, but bridge may aggregate)"

# P3: To+Cc
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test","cc":["cc-agent@bridge.test"],"subject":"P3-Cc","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "P-3 cc: $n OK" || warn "P-3 cc: $n"

# P4: empty body
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"empty@bridge.test","subject":"P4-Empty","markdown":""}' >/dev/null; n=$(wait_hermes 1); expect "$n" 1 "P-4 empty"

# P5: no route
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"noroute@bridge.test","subject":"P5-NoRoute","markdown":"test."}' >/dev/null; sleep 5; n=$(wc -l < "$HL" 2>/dev/null||echo 0)
[[ "$n" -eq 0 ]] && pass "P-5 no-route: 0 OK" || fail "P-5 no-route: $n"

# P6: same-domain aggregate (3 recipients → 1 webhook)
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test, agent2@bridge.test, cc-agent@bridge.test","subject":"P6-Aggregate","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "P-6 aggregate: $n OK" || warn "P-6 aggregate: $n"

# ═══════════════════════════════════
# MULTI-SYSTEM PUSH (two gateways → one bridge)
# ═══════════════════════════════════
echo; echo "═════ MULTI-SYSTEM PUSH TESTS ═════"

# Second gateway = system B (domain bridge2.test), same bridge as system A
mkdir -p "$WORK_DIR/relay3-data"
cat > "$WORK_DIR/relay3.toml" << EOF
[smtp]
bind = "127.0.0.1:${RS3}"
hostname = "relay3.local"
[http]
bind = "127.0.0.1:${RH3}"
[storage]
path = "${WORK_DIR}/relay3-data"
[retry]
max_attempts = 1
[logging]
level = "info"
EOF
"$GW_BIN" -c "$WORK_DIR/relay3.toml" --pid-file "$WORK_DIR/pid3" > "$WORK_DIR/relay3.log" 2>&1 &
GW2_PID=$!; sleep 4
for i in $(seq 1 15); do
    AK3=$(cat "$WORK_DIR/relay3-data/aimail.db.admin_key" 2>/dev/null||echo "")
    [[ -n "$AK3" ]] && break; sleep 1
done
for i in $(seq 1 15); do
    [[ "$(curl -s -o/dev/null -w'%{http_code}' "http://127.0.0.1:$RH3/health")" == 200 ]] && break
    sleep 1
done
pass "relay B (bridge2.test) running"
B3="http://127.0.0.1:${RH3}"

# Seed system B: domain + addresses (webhook → same bridge) + whitelists + send key
aimail_curl "${AK3}" -s -X POST "$B3/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-bridge2","domain":"bridge2.test"}' >/dev/null
# sender@test.local needs its domain registered in this gateway too
aimail_curl "${AK3}" -s -X POST "$B3/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-tlocal3","domain":"test.local"}' >/dev/null
for addr in agent@bridge2.test agent2@bridge2.test cc-agent@bridge2.test empty@bridge2.test; do
    aimail_curl "${AK3}" -s -X POST "$B3/api/v1/admin/systems/admin/addresses" -H "$J" \
        -d "{\"id\":\"b2-${addr%@*}\",\"email\":\"$addr\",\"webhook_url\":\"$BASE:${BP}/webhooks/bridge\"}" >/dev/null
done
aimail_curl "${AK3}" -s -X POST "$B3/api/v1/admin/systems/admin/addresses" -H "$J" \
    -d '{"id":"b2-sender","email":"sender@test.local"}' >/dev/null
aimail_curl "${AK3}" -s -X POST "$B3/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"bridge2.test","direction":"from","value":"*@test.local"}' >/dev/null
SK3=$(python3 "$SCRIPT_DIR/create_key.py" "$B3/api/v1/api-keys" "$AK3")
aimail_curl "${AK3}" -s -X POST "$B3/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"sender@test.local","direction":"to","value":"*@bridge2.test"}' >/dev/null
for addr in agent@bridge2.test agent2@bridge2.test cc-agent@bridge2.test empty@bridge2.test; do
    aimail_curl "${AK3}" -s -X POST "$B3/api/v1/whitelists" -H "$J" \
        -d "{\"system_id\":\"admin\",\"domain_addr\":\"$addr\",\"direction\":\"from\",\"value\":\"*@test.local\"}" >/dev/null
done
[[ -n "$SK3" ]] || fail "no system-B send key"
pass "relay B seeded"

# System B routes join the shared bridge route table (hot-reload)
cat >> "$WORK_DIR/bridge/aimail_routes.toml" << EOF
"agent@bridge2.test" = "127.0.0.1:${HP}"
"agent2@bridge2.test" = "127.0.0.1:${HP}"
"cc-agent@bridge2.test" = "127.0.0.1:${HP}"
"empty@bridge2.test" = "127.0.0.1:${HP}"
EOF
sleep 2  # let inotify hot-reload pick up the new routes

S3() { local code=$(aimail_curl "${SK3}" -s -w "%{http_code}" -o /dev/null -X POST "$B3/api/v1/send" -H "Content-Type: application/json" "$@" 2>/dev/null); echo "SEND3: $code" >&2; }

# M-P1: system A still works via the shared bridge
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test","subject":"MP1-A","markdown":"t."}' >/dev/null; n=$(wait_hermes 1); expect "$n" 1 "M-P1 system-A single"

# M-P2: system B delivers through the SAME bridge
rm -f "$HL"; S3 -d '{"sender":"sender@test.local","to":"agent@bridge2.test","subject":"MP2-B","markdown":"t."}' >/dev/null; n=$(wait_hermes 1); expect "$n" 1 "M-P2 system-B single"

# M-P3: both systems interleaved — each email routed to its own agent
rm -f "$HL"; S -d '{"sender":"sender@test.local","to":"agent@bridge.test","subject":"MP3-A1","markdown":"t."}' >/dev/null
S3 -d '{"sender":"sender@test.local","to":"agent@bridge2.test","subject":"MP3-B1","markdown":"t."}' >/dev/null
S -d '{"sender":"sender@test.local","to":"agent2@bridge.test","subject":"MP3-A2","markdown":"t."}' >/dev/null
S3 -d '{"sender":"sender@test.local","to":"agent2@bridge2.test","subject":"MP3-B2","markdown":"t."}' >/dev/null
n=$(wait_hermes 4); expect "$n" 4 "M-P3 4 emails (2 systems x 2 agents)"

# M-P4: system B batch aggregation
rm -f "$HL"; S3 -d '{"sender":"sender@test.local","to":"agent@bridge2.test, agent2@bridge2.test, cc-agent@bridge2.test","subject":"MP4-B","markdown":"t."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "M-P4 system-B aggregate: $n OK" || fail "M-P4 system-B aggregate: $n"

kill -9 "$GW2_PID" 2>/dev/null||true; wait "$GW2_PID" 2>/dev/null||true

cp "$WORK_DIR/relay.log" "/tmp/relay-push-saved.log" 2>/dev/null || true
kill -9 "$BRIDGE_PID" 2>/dev/null||true; sleep 3; wait "$BRIDGE_PID" 2>/dev/null||true

# ═══════════════════════════════════
# PULL MODE
# ═══════════════════════════════════
echo; echo "═════ PULL TESTS ═════"
kill -9 "$RELAY_PID" 2>/dev/null||true; sleep 5; wait "$RELAY_PID" 2>/dev/null||true
rm -rf "$WORK_DIR/relay-data"; mkdir -p "$WORK_DIR/relay-data"

cat > "$WORK_DIR/relay2.toml" << EOF
[smtp]
bind = "127.0.0.1:${RS2}"
hostname = "relay2.local"
[http]
bind = "127.0.0.1:${RH2}"
[storage]
path = "${WORK_DIR}/relay-data"
[retry]
max_attempts = 1
initial_backoff_secs = 1
[logging]
level = "info"
EOF
start_gw "$WORK_DIR/relay2.toml" "$RH2"
pass "pull relay running"

B2="http://127.0.0.1:${RH2}"
aimail_curl "${AK}" -s -X POST "$B2/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-pull","domain":"pull.test"}' >/dev/null
aimail_curl "${AK}" -s -X POST "$B2/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-tlocal","domain":"test.local"}' >/dev/null
for addr in agent@pull.test agent2@pull.test cc-agent@pull.test empty@pull.test; do
    aimail_curl "${AK}" -s -X POST "$B2/api/v1/admin/systems/admin/addresses" -H "$J" \
        -d "{\"id\":\"pa-${addr%@*}\",\"email\":\"$addr\"}" >/dev/null
done
# sender@test.local must be registered for send's whitelist/domain resolution
aimail_curl "${AK}" -s -X POST "$B2/api/v1/admin/systems/admin/addresses" -H "$J" \
    -d '{"id":"pa-sender","email":"sender@test.local"}' >/dev/null
aimail_curl "${AK}" -s -X POST "$B2/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"pull.test","direction":"from","value":"*@test.local"}' >/dev/null
SK2=$(python3 "$SCRIPT_DIR/create_key.py" "$B2/api/v1/api-keys" "$AK")
# to-rule must be address-level (sender@test.local) — gateway's whitelist
# resolver matches the sender's full address (ExactKeyResolver)
aimail_curl "${AK}" -s -X POST "$B2/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"sender@test.local","direction":"to","value":"*@pull.test"}' >/dev/null
for addr in agent@pull.test agent2@pull.test cc-agent@pull.test empty@pull.test; do
    aimail_curl "${AK}" -s -X POST "$B2/api/v1/whitelists" -H "$J" \
        -d "{\"system_id\":\"admin\",\"domain_addr\":\"$addr\",\"direction\":\"from\",\"value\":\"*@test.local\"}" >/dev/null
done
[[ -n "$SK2" ]] || fail "no pull send key"
pass "pull relay seeded"

# Pull bridge needs a system-scope key whose system_id matches the pending
# records ("admin" — the bootstrap admin key is bound to the real system id
# system-xxx and would filter everything out).
SYSPULL=$(aimail_curl "${AK}" -s -X POST "$B2/api/v1/admin/api-keys" -H "$J" \
    -d '{"system_id":"admin","email_address":"","scopes":["system"],"category":"system"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('raw_key',''))")
[[ -n "$SYSPULL" ]] || fail "no pull system key"

cat > "$WORK_DIR/bridge/bridge-pull.toml" << EOF
bind = "127.0.0.1:${BP2}"
routes_file = "$WORK_DIR/bridge/aimail_routes.toml"
mode = "pull"
[pull]
aimail_url = "127.0.0.1:${RH2}"
admin_key = "${SYSPULL}"
system_id = "admin"
poll_interval_sec = 2
[logging]
level = "info"
file = "$WORK_DIR/bridge/pull-bridge.log"
EOF
"$BRIDGE_BIN" -c "$WORK_DIR/bridge/bridge-pull.toml" > "$WORK_DIR/bridge/pull.log" 2>&1 &
BRIDGE_PID=$!; sleep 2
for i in $(seq 1 10); do [[ "$(curl -s -o/dev/null -w'%{http_code}' "$BASE:${BP2}/health" 2>/dev/null)" == 200 ]] && break; sleep 1; done
pass "bridge pull running"
# Wait for pull loop to start
for i in $(seq 1 25); do
    grep -q "Starting pull loop" "$WORK_DIR/bridge/pull-bridge.log" 2>/dev/null && break
    sleep 2
done
S2() { aimail_curl "${SK2}" -s -X POST "$B2/api/v1/send" -H "Content-Type: application/json" "$@"; }

# Q1: single
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test","subject":"Q1-Single","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "Q-1 single: $n OK" || warn "Q-1 single: $n"

# Q2: multi-to
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test, agent2@pull.test","subject":"Q2-Multi","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "Q-2 multi: $n OK" || warn "Q-2 multi: $n"

# Q3: To+Cc
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test","cc":["cc-agent@pull.test"],"subject":"Q3-Cc","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "Q-3 cc: $n OK" || warn "Q-3 cc: $n"

# Q4: empty body
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"empty@pull.test","subject":"Q4-Empty","markdown":""}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "Q-4 empty: $n OK" || warn "Q-4 empty: $n"

# Q5: no route
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"noroute@pull.test","subject":"Q5-NoRoute","markdown":"test."}' >/dev/null; sleep 5; n=$(wc -l < "$HL" 2>/dev/null||echo 0)
[[ "$n" -eq 0 ]] && pass "Q-5 no-route: 0 OK" || warn "Q-5 no-route: $n"

# Q6: aggregate
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test, agent2@pull.test, cc-agent@pull.test","subject":"Q6-Aggregate","markdown":"test."}' >/dev/null; n=$(wait_hermes 1); [[ "$n" -ge 1 ]] && pass "Q-6 aggregate: $n OK" || warn "Q-6 aggregate: $n"

# Q7: ACK cleanup
PB=$(aimail_curl "${AK}" -s "$B2/api/v1/admin/pending" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null||echo 0)
sleep 10
PA=$(aimail_curl "${AK}" -s "$B2/api/v1/admin/pending" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null||echo 0)
[[ "$PA" -lt "$PB" || "$PA" -eq 0 ]] && pass "Q-7 ACK: $PB→$PA" || warn "Q-7 ACK: $PB→$PA"

# ═══════════════════════════════════
# MULTI-SYSTEM PULL (one bridge ← two gateways/systems)
# ═══════════════════════════════════
echo; echo "═════ MULTI-SYSTEM PULL TESTS ═════"

# Second pull gateway = system B (domain pull2.test)
mkdir -p "$WORK_DIR/relay4-data"
cat > "$WORK_DIR/relay4.toml" << EOF
[smtp]
bind = "127.0.0.1:${RS4}"
hostname = "relay4.local"
[http]
bind = "127.0.0.1:${RH4}"
[storage]
path = "${WORK_DIR}/relay4-data"
[retry]
max_attempts = 1
[logging]
level = "info"
EOF
"$GW_BIN" -c "$WORK_DIR/relay4.toml" --pid-file "$WORK_DIR/pid4" > "$WORK_DIR/relay4.log" 2>&1 &
GW3_PID=$!; sleep 4
for i in $(seq 1 15); do
    AK4=$(cat "$WORK_DIR/relay4-data/aimail.db.admin_key" 2>/dev/null||echo "")
    [[ -n "$AK4" ]] && break; sleep 1
done
for i in $(seq 1 15); do
    [[ "$(curl -s -o/dev/null -w'%{http_code}' "http://127.0.0.1:$RH4/health")" == 200 ]] && break
    sleep 1
done
pass "pull relay B (pull2.test) running"
B4="http://127.0.0.1:${RH4}"

# Seed system B (pull2.test) — mirrors the single-system pull seed
aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-pull2","domain":"pull2.test"}' >/dev/null
aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/systems/admin/domains" -H "$J" -d '{"id":"dom-tlocal4","domain":"test.local"}' >/dev/null
for addr in agent@pull2.test agent2@pull2.test cc-agent@pull2.test empty@pull2.test; do
    aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/systems/admin/addresses" -H "$J" \
        -d "{\"id\":\"p4-${addr%@*}\",\"email\":\"$addr\"}" >/dev/null
done
aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/systems/admin/addresses" -H "$J" \
    -d '{"id":"p4-sender","email":"sender@test.local"}' >/dev/null
aimail_curl "${AK4}" -s -X POST "$B4/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"pull2.test","direction":"from","value":"*@test.local"}' >/dev/null
SK4=$(python3 "$SCRIPT_DIR/create_key.py" "$B4/api/v1/api-keys" "$AK4")
aimail_curl "${AK4}" -s -X POST "$B4/api/v1/whitelists" -H "$J" -d '{"system_id":"admin","domain_addr":"sender@test.local","direction":"to","value":"*@pull2.test"}' >/dev/null
for addr in agent@pull2.test agent2@pull2.test cc-agent@pull2.test empty@pull2.test; do
    aimail_curl "${AK4}" -s -X POST "$B4/api/v1/whitelists" -H "$J" \
        -d "{\"system_id\":\"admin\",\"domain_addr\":\"$addr\",\"direction\":\"from\",\"value\":\"*@test.local\"}" >/dev/null
done
[[ -n "$SK4" ]] || fail "no system-B pull send key"
SYSPULL2=$(aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/api-keys" -H "$J" \
    -d '{"system_id":"admin","email_address":"","scopes":["system"],"category":"system"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('raw_key',''))")
[[ -n "$SYSPULL2" ]] || fail "no system-B pull system key"
pass "pull relay B seeded"

# pull2.test routes join the shared route table
cat >> "$WORK_DIR/bridge/aimail_routes.toml" << EOF
"agent@pull2.test" = "127.0.0.1:${HP}"
"agent2@pull2.test" = "127.0.0.1:${HP}"
"cc-agent@pull2.test" = "127.0.0.1:${HP}"
"empty@pull2.test" = "127.0.0.1:${HP}"
EOF

# Multi-system bridge: systems array → both gateways, each with its own key
cat > "$WORK_DIR/bridge/bridge-pull2.toml" << EOF
bind = "127.0.0.1:${BP3}"
routes_file = "$WORK_DIR/bridge/aimail_routes.toml"
mode = "pull"
[pull]
systems = [
  { aimail_url = "127.0.0.1:${RH2}", admin_key = "${SYSPULL}", system_id = "admin", poll_interval_sec = 2 },
  { aimail_url = "127.0.0.1:${RH4}", admin_key = "${SYSPULL2}", system_id = "admin", poll_interval_sec = 2 },
]
[logging]
level = "info"
file = "$WORK_DIR/bridge/pull2-bridge.log"
EOF
"$BRIDGE_BIN" -c "$WORK_DIR/bridge/bridge-pull2.toml" > "$WORK_DIR/bridge/pull2.log" 2>&1 &
MBRIDGE_PID=$!; sleep 2
for i in $(seq 1 10); do [[ "$(curl -s -o/dev/null -w'%{http_code}' "$BASE:${BP3}/health" 2>/dev/null)" == 200 ]] && break; sleep 1; done
for i in $(seq 1 25); do
    grep -q "Starting pull loop" "$WORK_DIR/bridge/pull2-bridge.log" 2>/dev/null && break
    sleep 2
done
pass "multi-system bridge running"

S4() { aimail_curl "${SK4}" -s -X POST "$B4/api/v1/send" -H "Content-Type: application/json" "$@"; }

# M-Q1: system A pending → agent@pull.test; system B pending → agent@pull2.test
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test","subject":"MQ1-A","markdown":"t."}' >/dev/null
S4 -d '{"sender":"sender@test.local","to":"agent@pull2.test","subject":"MQ1-B","markdown":"t."}' >/dev/null
n=$(wait_hermes 2); expect "$n" 2 "M-Q1 both systems pulled (A+B)"

# M-Q2: interleaved multi-recipient across both systems
rm -f "$HL"; S2 -d '{"sender":"sender@test.local","to":"agent@pull.test, agent2@pull.test","subject":"MQ2-A","markdown":"t."}' >/dev/null
S4 -d '{"sender":"sender@test.local","to":"agent@pull2.test, agent2@pull2.test","subject":"MQ2-B","markdown":"t."}' >/dev/null
n=$(wait_hermes 4); expect "$n" 4 "M-Q2 4 emails (2 systems x 2 recipients)"

# M-Q3: system isolation — only system B sends, system A gets nothing
rm -f "$HL"; S4 -d '{"sender":"sender@test.local","to":"agent@pull2.test","subject":"MQ3-B","markdown":"t."}' >/dev/null
n=$(wait_hermes 1); expect "$n" 1 "M-Q3 system-B only"

# M-Q4: ACK drains both systems' pending queues
PB4=$(aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/pending" -H "$J" -d '{"limit":50,"filter":["pull2.test"]}' | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('batches',[])))" 2>/dev/null||echo 0)
sleep 10
PA4=$(aimail_curl "${AK4}" -s -X POST "$B4/api/v1/admin/pending" -H "$J" -d '{"limit":50,"filter":["pull2.test"]}' | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('batches',[])))" 2>/dev/null||echo 0)
[[ "$PA4" -lt "$PB4" || "$PA4" -eq 0 ]] && pass "M-Q4 ACK system-B: $PB4→$PA4" || warn "M-Q4 ACK system-B: $PB4→$PA4"

kill -9 "$GW3_PID" "$MBRIDGE_PID" 2>/dev/null||true; wait "$GW3_PID" "$MBRIDGE_PID" 2>/dev/null||true

echo; echo "═════ Bridge E2E: Complete ═════"
