#!/usr/bin/env bash
# test_vuln_php.sh — exercise every vulnerable PHP endpoint through three
# data-paths and verify WAFio catches the attack while letting benign
# traffic through.
#
# Data-paths:
#   (A) backend-only  :8088  (NO WAF)   — reached via ssh from server itself
#   (B) inline-waf    :8090  (WAF)      — reached from the caller (Mac)
#   (C) edge-nginx    :8091 → :8090     — production layout
#
# Host header matters: the agent only has --waf-keys for `hello.local`, so
# all proxy-path calls need `Host: hello.local`.
#
#   SSH_HOST=<lab host> SSH_USER=<ssh user> SSH_PASS=<ssh password> \
#     ./test/test_vuln_php.sh
#
# The three SSH_* variables are required; the script has no defaults for them.

set -u
SSH_HOST="${SSH_HOST:?set SSH_HOST to the lab server}"
SSH_USER="${SSH_USER:?set SSH_USER}"
SSH_PASS="${SSH_PASS:?set SSH_PASS}"
HOST_HEADER="${HOST_HEADER:-hello.local}"

INLINE="http://${SSH_HOST}:8090"
EDGE="http://${SSH_HOST}:8091"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; CYA=$'\033[0;36m'; RST=$'\033[0m'
PASS=0; FAIL=0
label() { printf '\n%s%s%s\n' "$CYA" "$*" "$RST"; }

assert_code() {
    local want="$1" got="$2" name="$3"
    if [ "$got" = "$want" ]; then
        printf '  %sPASS%s  %-48s want=%s got=%s\n' "$GRN" "$RST" "$name" "$want" "$got"
        PASS=$((PASS+1))
    else
        printf '  %sFAIL%s  %-48s want=%s got=%s\n' "$RED" "$RST" "$name" "$want" "$got"
        FAIL=$((FAIL+1))
    fi
}

# local_get <url>                                 → HTTP code, Host=hello.local
local_get() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        -H "Host: ${HOST_HEADER}" "$1"
}
# local_post_form <url> <body>                    → HTTP code, Host=hello.local, form-urlencoded
local_post_form() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        -H "Host: ${HOST_HEADER}" -X POST --data-binary "$2" "$1"
}
# local_post_json <url> <json>
local_post_json() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        -H "Host: ${HOST_HEADER}" -H 'Content-Type: application/json' \
        -X POST --data-binary "$2" "$1"
}

# backend_* → run curl on the server itself (127.0.0.1:8088 is loopback-only).
# Each helper writes the payload to a file on the server first, then curl --data-binary @/tmp/file — this avoids every shell-escape landmine.
BACKEND_SSH=(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "${SSH_USER}@${SSH_HOST}")

backend_get() {                                    # $1 = path
    "${BACKEND_SSH[@]}" "curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: ${HOST_HEADER}' 'http://127.0.0.1:8088$1'" 2>/dev/null
}
backend_post_form() {                              # $1 = path, $2 = raw body
    printf '%s' "$2" | "${BACKEND_SSH[@]}" "cat >/tmp/wafio_test.body && curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: ${HOST_HEADER}' -X POST --data-binary @/tmp/wafio_test.body 'http://127.0.0.1:8088$1'" 2>/dev/null
}
backend_post_json() {                              # $1 = path, $2 = json body
    printf '%s' "$2" | "${BACKEND_SSH[@]}" "cat >/tmp/wafio_test.body && curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: ${HOST_HEADER}' -H 'Content-Type: application/json' -X POST --data-binary @/tmp/wafio_test.body 'http://127.0.0.1:8088$1'" 2>/dev/null
}

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  WAFio — Vulnerable PHP Demo Test Suite                          ║"
echo "║  server=${SSH_HOST}  host-header=${HOST_HEADER}                     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

label "[0] Liveness"
assert_code 200 "$(backend_get /)"       "backend          GET /"
assert_code 200 "$(local_get ${INLINE}/)" "inline waf       GET /"
assert_code 200 "$(local_get ${EDGE}/)"   "edge nginx       GET /"

# ============================================================ 1. SQLi (GET)
# NOTE: real attacks use `--` to cut the tail of the query, so the payload
# below uses that form, as tools like sqlmap do. "admin' OR 1=1" alone is
# also an attack, but a bare tautology without a terminator is the shape
# most likely to appear in ordinary text.
label "[1] SQL injection — login.php (GET)"
SQLI_QS="username=admin%27+OR+1%3D1--&password=x"
assert_code 200 "$(local_get ${INLINE}/login.php)"             "inline  benign"
assert_code 200 "$(local_get ${EDGE}/login.php)"               "edge    benign"
assert_code 200 "$(backend_get "/login.php?${SQLI_QS}")"       "backend SQLi (no WAF)     → unsafe"
assert_code 403 "$(local_get "${INLINE}/login.php?${SQLI_QS}")" "inline  SQLi blocked"
assert_code 403 "$(local_get "${EDGE}/login.php?${SQLI_QS}")"   "edge    SQLi blocked"

# ============================================================ 2. SQLi (POST form)
label "[2] SQL injection — login.php (POST form-urlencoded)"
POSTSQLI="username=admin%27+OR+1%3D1--&password=x"
assert_code 200 "$(backend_post_form /login.php "$POSTSQLI")"     "backend POST SQLi (no WAF) → unsafe"
assert_code 403 "$(local_post_form ${INLINE}/login.php "$POSTSQLI")" "inline  POST SQLi blocked"
assert_code 403 "$(local_post_form ${EDGE}/login.php   "$POSTSQLI")" "edge    POST SQLi blocked"

# ============================================================ 3. Reflected XSS
label "[3] Reflected XSS — search.php"
XSS_QS="q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
assert_code 200 "$(local_get "${INLINE}/search.php?q=hello")"    "inline  benign"
assert_code 200 "$(backend_get "/search.php?${XSS_QS}")"         "backend XSS (no WAF)      → unsafe"
assert_code 403 "$(local_get "${INLINE}/search.php?${XSS_QS}")"  "inline  XSS blocked"
assert_code 403 "$(local_get "${EDGE}/search.php?${XSS_QS}")"    "edge    XSS blocked"

# ============================================================ 4. LFI / path traversal
label "[4] LFI — read.php"
LFI_QS="file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
assert_code 200 "$(local_get "${INLINE}/read.php?file=hello.txt")" "inline  benign"
assert_code 200 "$(backend_get "/read.php?${LFI_QS}")"             "backend LFI (no WAF)      → unsafe"
assert_code 403 "$(local_get "${INLINE}/read.php?${LFI_QS}")"      "inline  LFI blocked"
assert_code 403 "$(local_get "${EDGE}/read.php?${LFI_QS}")"        "edge    LFI blocked"

# ============================================================ 5. Command injection
label "[5] Command injection — ping.php"
RCE_QS="host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd"
assert_code 200 "$(local_get "${INLINE}/ping.php?host=127.0.0.1")" "inline  benign"
assert_code 200 "$(backend_get "/ping.php?${RCE_QS}")"             "backend RCE (no WAF)      → unsafe"
assert_code 403 "$(local_get "${INLINE}/ping.php?${RCE_QS}")"      "inline  RCE blocked"
assert_code 403 "$(local_get "${EDGE}/ping.php?${RCE_QS}")"        "edge    RCE blocked"

# ============================================================ 6. JSON body attack
label "[6] JSON body — upload.php"
JSONOK='{"comment":"hello world"}'
JSONBAD='{"comment":"<script>alert(1)</script>"}'
assert_code 200 "$(local_post_json  ${INLINE}/upload.php "$JSONOK")"   "inline  benign JSON"
assert_code 200 "$(backend_post_json /upload.php "$JSONBAD")"           "backend JSON XSS (no WAF) → unsafe"
assert_code 403 "$(local_post_json  ${INLINE}/upload.php "$JSONBAD")"  "inline  JSON XSS blocked"
assert_code 403 "$(local_post_json  ${EDGE}/upload.php   "$JSONBAD")"  "edge    JSON XSS blocked"

# ============================================================ 7. Unknown Host should NOT bypass
label "[7] Unknown Host header → still blocked"
BAD_HOST_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
    -H 'Host: unknown.example.com' "${INLINE}/ping.php?${RCE_QS}")
assert_code 403 "$BAD_HOST_CODE" "inline  unknown Host still blocks RCE"

# ============================================================ 8. Latency sanity
label "[8] Latency — 5 benign requests via edge"
for i in 1 2 3 4 5; do
    ms=$(curl -s -o /dev/null -w '%{time_total}' --max-time 6 \
        -H "Host: ${HOST_HEADER}" "${EDGE}/")
    printf '  edge #%d  %ss\n' "$i" "$ms"
done

echo
echo "──────────────────────────────────────────────────────────"
printf ' summary: %s%d pass%s · %s%d fail%s\n' "$GRN" "$PASS" "$RST" "$RED" "$FAIL" "$RST"
echo "──────────────────────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
