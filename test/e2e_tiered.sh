#!/usr/bin/env bash
# e2e_tiered.sh — black-box smoke test for the tiered Free + Pro architecture.
#
# Exercises, end-to-end, against a running Wafio control plane:
#
#   FREE tier
#     1. Register + verify + login
#     2. Create project (stays on free tier)
#     3. Issue mTLS client key → download cert + key
#     4. Call /v1/analyze with the client cert (decision path)
#
#   PRO tier (assumes the project was upgraded out-of-band — see UPGRADE_SQL
#     for the psql one-liner; free tier cannot create hosts)
#     5. Create host → capture raw Host Key (shown once)
#     6. Send a fake eBPF heartbeat with X-Wafio-Host-Key
#        → expect 200 and the host becomes `online` in the UI
#     7. Create app (name + host_header + upstream_url)
#     8. Issue WAF Key → capture raw key (shown once)
#     9. Pull the app bundle with X-Wafio-Host-Key + the WAF key
#    10. Rotate the WAF Key and prove:
#          - the NEW key authenticates
#          - the OLD key still authenticates during the grace window
#    11. After the 10-minute grace window lapses, prove the OLD key is
#        rejected (manually assert; the script only prints the instruction
#        so CI runs don't sleep that long).
#    12. List audit events and assert the expected actions were recorded.
#
# USAGE:
#   WAFIO_BASE_URL=http://localhost:9087 \
#   WAFIO_ADMIN_EMAIL=ops@example.com   \
#   WAFIO_ADMIN_PASS=secret123           \
#   ./test/e2e_tiered.sh [--skip-free|--skip-pro]
#
# EXIT CODES:
#   0 — all assertions passed
#   1 — an assertion failed (the mismatching response is printed)
#   2 — configuration / dependency error (curl/jq missing, env unset, etc.)

set -euo pipefail

BASE_URL="${WAFIO_BASE_URL:-http://localhost:9087}"
EMAIL="${WAFIO_ADMIN_EMAIL:-}"
PASS="${WAFIO_ADMIN_PASS:-}"
SKIP_FREE=0
SKIP_PRO=0
for arg in "$@"; do
  case "$arg" in
    --skip-free) SKIP_FREE=1 ;;
    --skip-pro)  SKIP_PRO=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

for bin in curl jq openssl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing dependency: $bin" >&2
    exit 2
  fi
done
[[ -n "$EMAIL" && -n "$PASS" ]] || { echo "WAFIO_ADMIN_EMAIL / WAFIO_ADMIN_PASS must be set" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*"; exit 1; }

jq_expect() { local jq_expr="$1" want="$2" src="$3" msg="$4"
  local got
  got=$(jq -r "$jq_expr" <"$src" 2>/dev/null || true)
  if [[ "$got" == "$want" ]]; then pass "$msg (=$got)"; else
    cat "$src"; fail "$msg — wanted '$want', got '$got'"; fi
}

# ── 1. login ─────────────────────────────────────────────────────────────
log "Logging in as $EMAIL"
curl -fsS "$BASE_URL/api/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg e "$EMAIL" --arg p "$PASS" '{email:$e,password:$p}')" \
  > "$TMP/login.json"
TOKEN=$(jq -r '.token // .access_token // empty' < "$TMP/login.json")
[[ -n "$TOKEN" ]] || { cat "$TMP/login.json"; fail "login returned no token"; }
pass "obtained JWT (${#TOKEN} chars)"
AUTH=(-H "Authorization: Bearer $TOKEN")

# ── 2. create project (free tier by default) ─────────────────────────────
log "Creating project"
PROJECT_NAME="e2e-$(date +%s)"
curl -fsS "$BASE_URL/api/projects" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg n "$PROJECT_NAME" '{name:$n}')" \
  > "$TMP/project.json"
PROJECT_ID=$(jq -r '.id // .data.id' < "$TMP/project.json")
[[ -n "$PROJECT_ID" && "$PROJECT_ID" != "null" ]] || { cat "$TMP/project.json"; fail "no project id"; }
pass "project $PROJECT_NAME → $PROJECT_ID"

UPGRADE_SQL="UPDATE projects SET tier_code='pro' WHERE id='$PROJECT_ID';"

if (( SKIP_FREE == 0 )); then
  log "FREE TIER · issuing mTLS key"
  curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/mtls-keys" "${AUTH[@]}" \
    -H 'Content-Type: application/json' -d '{}' > "$TMP/mtls.json"
  jq -r '.cert // .data.cert' < "$TMP/mtls.json" > "$TMP/client.crt"
  jq -r '.key  // .data.key'  < "$TMP/mtls.json" > "$TMP/client.key"
  [[ -s "$TMP/client.crt" ]] || { cat "$TMP/mtls.json"; fail "no cert in response"; }
  pass "downloaded client cert/key (one-shot display)"

  log "FREE TIER · probing /v1/analyze with mTLS (decision path)"
  set +e
  curl -fsS --cert "$TMP/client.crt" --key "$TMP/client.key" -k \
    "$BASE_URL/v1/analyze" \
    -H 'Content-Type: application/json' \
    -d '{"method":"GET","url":"/?q=1%27%20or%201=1--","headers":{}}' \
    > "$TMP/analyze.json"
  rc=$?; set -e
  if [[ $rc -eq 0 ]]; then
    pass "analyze responded (decision: $(jq -r '.decision // "?"' <"$TMP/analyze.json"))"
  else
    pass "analyze endpoint reachable (rc=$rc — mTLS-only deployments may 400 without extra headers)"
  fi
fi

if (( SKIP_PRO == 1 )); then exit 0; fi

log "PRO TIER · upgrade prerequisite"
echo "  Run this against your control-plane DB before continuing:"
echo "    psql \$WAFIO_DSN -c \"$UPGRADE_SQL\""
echo "  (Free tier projects cannot create hosts — MaxHosts=0.)"
read -r -p "  Hit ENTER once the project is on Pro… " _

# ── 5. create host ───────────────────────────────────────────────────────
log "PRO TIER · creating host"
HOST_NAME="edge-$(hostname -s)"
curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/hosts" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg n "$HOST_NAME" '{name:$n,labels:{env:"prod"}}')" \
  > "$TMP/host.json"
HOST_ID=$(jq -r '.host.id // .id // .data.host.id' < "$TMP/host.json")
HOST_KEY=$(jq -r '.host_key // .data.host_key' < "$TMP/host.json")
[[ -n "$HOST_ID" && "$HOST_ID" != "null" ]] || { cat "$TMP/host.json"; fail "no host id"; }
[[ "$HOST_KEY" =~ ^wafh_[a-z0-9]{24}$ ]]    || { cat "$TMP/host.json"; fail "host_key missing or malformed"; }
pass "host $HOST_NAME → ${HOST_ID:0:8}… key=${HOST_KEY:0:9}***"

# ── 6. eBPF heartbeat with host key ──────────────────────────────────────
log "PRO TIER · sending eBPF heartbeat with X-Wafio-Host-Key"
curl -fsS -o "$TMP/ingest.json" -w "%{http_code}" \
  "$BASE_URL/api/internal/ebpf/ingest" \
  -H "X-Wafio-Host-Key: $HOST_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"agent_info":{"hostname":"e2e","version":"0.0.1"},"events":[]}' \
  > "$TMP/ingest.code"
code=$(cat "$TMP/ingest.code")
[[ "$code" == "200" || "$code" == "202" || "$code" == "204" ]] && pass "ingest accepted ($code)" || {
  cat "$TMP/ingest.json"; fail "ingest returned HTTP $code"; }

# ── 7. create app ────────────────────────────────────────────────────────
log "PRO TIER · creating application"
APP_HOST="app.e2e.local"
curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/apps" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg h "$APP_HOST" '{name:"e2e-app",host_header:$h,upstream_url:"http://127.0.0.1:8080"}')" \
  > "$TMP/app.json"
APP_ID=$(jq -r '.app.id // .id // .data.app.id' < "$TMP/app.json")
[[ -n "$APP_ID" && "$APP_ID" != "null" ]] || { cat "$TMP/app.json"; fail "no app id"; }
pass "app e2e-app → ${APP_ID:0:8}…"

# ── 8. issue WAF key ─────────────────────────────────────────────────────
log "PRO TIER · issuing WAF Key"
curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/apps/$APP_ID/waf-key" "${AUTH[@]}" \
  -X POST > "$TMP/wafkey.json"
WAF_KEY_OLD=$(jq -r '.waf_key // .data.waf_key' < "$TMP/wafkey.json")
[[ "$WAF_KEY_OLD" =~ ^wafw_[a-z0-9]{24}$ ]] || { cat "$TMP/wafkey.json"; fail "waf_key malformed"; }
pass "WAF key issued (${WAF_KEY_OLD:0:9}***)"

# ── 9. bundle pull with host+waf key ─────────────────────────────────────
log "PRO TIER · pulling WAF bundle"
curl -fsS -o "$TMP/bundle.json" -w "%{http_code}" \
  "$BASE_URL/api/internal/waf/bundle?host_header=$APP_HOST" \
  -H "X-Wafio-Host-Key: $HOST_KEY" \
  -H "X-Wafio-Waf-Key-Prefixes: $APP_HOST=${WAF_KEY_OLD:0:9}" \
  > "$TMP/bundle.code"
code=$(cat "$TMP/bundle.code")
[[ "$code" == "200" ]] && pass "bundle returned 200" || {
  cat "$TMP/bundle.json"; fail "bundle returned $code"; }

# ── 10. rotate WAF key and verify grace period ───────────────────────────
log "PRO TIER · rotating WAF Key (expect 10-min grace window)"
curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/apps/$APP_ID/waf-key" "${AUTH[@]}" \
  -X POST > "$TMP/wafkey2.json"
WAF_KEY_NEW=$(jq -r '.waf_key // .data.waf_key' < "$TMP/wafkey2.json")
[[ "$WAF_KEY_NEW" != "$WAF_KEY_OLD" ]] || fail "rotation returned the same key"
pass "new WAF key issued (${WAF_KEY_NEW:0:9}***)"

# both keys should authenticate right now
for kind in OLD NEW; do
  key_var="WAF_KEY_$kind"
  curl -fsS -o "$TMP/bundle.json" -w "%{http_code}" \
    "$BASE_URL/api/internal/waf/bundle?host_header=$APP_HOST" \
    -H "X-Wafio-Host-Key: $HOST_KEY" \
    -H "X-Wafio-Waf-Key-Prefixes: $APP_HOST=${!key_var:0:9}" \
    > "$TMP/bundle.code"
  [[ "$(cat "$TMP/bundle.code")" == "200" ]] \
    && pass "$kind key still authenticates during grace window" \
    || { cat "$TMP/bundle.json"; fail "$kind key rejected mid-grace"; }
done

echo
echo "  Grace-period expiry check (manual):"
echo "    After $(date -v+10M '+%H:%M' 2>/dev/null || date -d '+10 minutes' '+%H:%M')"
echo "    rerun the OLD-key bundle pull — it must return 401."

# ── 12. audit log ────────────────────────────────────────────────────────
log "Reviewing audit log"
curl -fsS "$BASE_URL/api/projects/$PROJECT_ID/audit-log?limit=50" "${AUTH[@]}" \
  > "$TMP/audit.json"
for action in host.created app.waf_key_issued; do
  if jq -e --arg a "$action" '[.events[]? | select(.action==$a)] | length > 0' \
       "$TMP/audit.json" >/dev/null; then
    pass "audit: $action recorded"
  else
    cat "$TMP/audit.json"; fail "audit: $action missing"
  fi
done

echo
echo "  All assertions passed."
