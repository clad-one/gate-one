#!/usr/bin/env bash
# Cladone Gate One smoke test: starts a fake backend + a gateway with a pwa
# route and an authenticated MCP route, then checks HTML injection,
# manifest, sw.js, self-hosted workbox runtime, and the MCP circuit
# (configured scope, X-MCP-Scope header to the fake auth-bridge, 401
# challenge, metadata). Used by `make smoke` (at the root).
set -euo pipefail

cd "$(dirname "$0")"

PORT_GW=3999
PORT_BE=3998
PORT_AB=3997

routes_tmp=$(mktemp /tmp/gw-smoke-routes.XXXX.json)
backend_tmp=$(mktemp /tmp/gw-smoke-backend.XXXX.py)
bridge_tmp=$(mktemp /tmp/gw-smoke-bridge.XXXX.js)
scopes_tmp=/tmp/gw-smoke-scopes.$$
gw_log=$(mktemp /tmp/gw-smoke-gwlog.XXXX)
# gw_log is kept after the run (for diagnostics): /tmp/gw-smoke-gwlog.*
trap 'kill $GW_PID $BE_PID $AB_PID 2>/dev/null || true; rm -f "$routes_tmp" "$backend_tmp" "$bridge_tmp" "$scopes_tmp"' EXIT

cat > "$routes_tmp" <<EOF
{
  "routes": [
    {
      "host": "smoke.local",
      "path": "/*",
      "frontend": true,
      "backend": "http://127.0.0.1:${PORT_BE}",
      "pwa": { "enabled": true, "name": "SmokeApp" }
    },
    {
      "host": "mcp.smoke.local",
      "path": "/mcp",
      "backend": "http://127.0.0.1:${PORT_BE}",
      "auth": {},
      "mcp": {
        "enabled": true,
        "path": "/mcp",
        "scope": "smoke-scope",
        "operations": []
      }
    },
    {
      "host": "upstream.smoke.local",
      "path": "/*",
      "frontend": true,
      "backend": "http://127.0.0.1:${PORT_BE}",
      "upstream": {
        "host": true,
        "headers": {
          "Authorization": "Basic \${SMOKE_UPSTREAM_TOKEN}",
          "X-Strip-Me": ""
        },
        "rewriteRedirects": true,
        "responseHeaders": {
          "remove": ["Content-Security-Policy"],
          "set": {"X-Gate-One-Smoke": "upstream"}
        }
      }
    }
  ]
}
EOF

cat > "$backend_tmp" <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json


class H(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/':
            b = b'<html><head><meta charset="utf-8"><title>smoke</title></head><body>ok</body></html>'
            self._send(200, 'text/html; charset=utf-8', b)
        elif u.path == '/echo':
            b = json.dumps({
                'host': self.headers.get('Host', ''),
                'authorization': self.headers.get('Authorization', ''),
                'custom': self.headers.get('X-Custom', ''),
                'strip_present': self.headers.get('X-Strip-Me') is not None,
            }).encode()
            self._send(200, 'application/json', b)
        elif u.path == '/redirect':
            self.send_response(302)
            self.send_header(
                'Location', parse_qs(u.query).get('loc', ['/'])[0])
            self.send_header('Content-Length', '0')
            self.end_headers()
        elif u.path == '/gz':
            import io
            import gzip as gz
            buf = io.BytesIO()
            with gz.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(b'<html><head><title>gz</title></head>'
                        b'<body>gzip-ok</body></html>')
            self._send(200, 'text/html; charset=utf-8', buf.getvalue(),
                       extra={'Content-Encoding': 'gzip'})
        elif u.path == '/big':
            b = (b'<html><head><title>big</title></head><body>'
                 + b'x' * (3 * 1024 * 1024 // 2)
                 + b'</body></html>')
            self._send(200, 'text/html; charset=utf-8', b)
        elif u.path == '/page':
            b = b'<html><head><title>upstream smoke</title></head><body>x</body></html>'
            self._send(200, 'text/html; charset=utf-8', b, extra={
                'Content-Security-Policy': "default-src 'self'"})
        else:
            self.send_response(404)
            self.end_headers()


HTTPServer(('127.0.0.1', int(__import__('sys').argv[1])), H).serve_forever()
EOF

# Fake auth-bridge: logs the received X-MCP-Scope header and always
# replies 401 — the gateway must turn that into a Bearer challenge
# carrying the configured scope.
cat > "$bridge_tmp" <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer

SCOPES_FILE = __import__('sys').argv[2]


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        scope = self.headers.get('X-MCP-Scope', '')
        with open(SCOPES_FILE, 'a') as f:
            f.write(scope + '\n')
        self.send_response(401)
        self.send_header('Content-Length', '0')
        self.end_headers()


HTTPServer(('127.0.0.1', int(__import__('sys').argv[1])), H).serve_forever()
EOF

python3 "$backend_tmp" "$PORT_BE" & BE_PID=$!
python3 "$bridge_tmp" "$PORT_AB" "$scopes_tmp" & AB_PID=$!
# SMOKE_UPSTREAM_TOKEN: read by the gateway at load time (${...}
# interpolation in the upstream policy) — exactly as in production.
# -authBridge: the gateway must query the local STUB (without the flag,
# it would call the Docker service name auth-bridge:3000).
SMOKE_UPSTREAM_TOKEN=YmFzaWMtdG9rZW4= \
  ./bin/gate-one -config "$routes_tmp" -addr ":${PORT_GW}" \
    -authBridge "http://127.0.0.1:${PORT_AB}" > "$gw_log" 2>&1 & GW_PID=$!

# debug: all 3 services must be listening — robust wait (a plain
# `sleep 1` is racy under load, and set -e + exec + /dev/tcp inside an
# isolated if kills the script silently; use a function with retry,
# invoked with || to disarm set -e).
wait_port() {
  local port=$1 name=$2 i
  for i in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "SMOKE FAIL: ${name} on :${port} is not listening" >&2
  return 1
}
wait_port "$PORT_BE" backend || exit 1
wait_port "$PORT_AB" auth-bridge || exit 1
wait_port "$PORT_GW" gateway || exit 1

fail() {
  echo "SMOKE FAIL: $1" >&2
  echo "--- gateway log ---" >&2
  cat "${gw_log:-/dev/null}" >&2 || true
  exit 1
}

step() { echo "… $1" >&2; }

# grep_body: match against a body that is FULLY read first. Never use
# `curl | grep -q` at the head of a pipe: grep -q exits at the first
# match → random SIGPIPE on curl → pipefail → flaky check depending on
# scheduling (~28 KB body with the guard: frequent race).
grep_body() {
  local pattern=$1; shift
  local body
  body=$(curl -sf "$@") || return 1
  grep -q "$pattern" <<<"$body"
}

step "HTML injection"
grep_body '<link rel="manifest" href="/__gate-one_pwa/manifest.json">' \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/" \
    || fail "manifest link not injected in HTML"

# the site's meta charset must stay within the browser detection
# window (first 1024 bytes) after the guard is injected — otherwise
# the document is decoded as windows-1252 ("DÃ©connexion")
meta_pos=$(curl -sf -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/" \
    | grep -bo 'charset=' | head -1 | cut -d: -f1)
[ -n "$meta_pos" ] && [ "$meta_pos" -lt 1024 ] \
    || fail "meta charset outside browser detection window (position: ${meta_pos:-absent})"

grep_body '"name": "SmokeApp"' \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gate-one_pwa/manifest.json" \
    || fail "manifest not served / wrong name"

grep_body "modulePathPrefix: '/__gate-one_pwa/workbox/'" \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gate-one_pwa/sw.js" \
    || fail "sw.js not self-hosted"

grep_body "workbox" \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gate-one_pwa/workbox/workbox-sw.js" \
    || fail "embedded workbox runtime not served"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: smoke.local" \
    "http://127.0.0.1:${PORT_GW}/__gate-one_pwa/workbox/../pwa.go")
[ "$code" = "404" ] || fail "path traversal not blocked (got $code)"

# --- MCP circuit ---
step "MCP circuit (X-MCP-Scope → auth-bridge)"
# 1) the fake auth-bridge receives the route's configured scope (not
#    the mcp-tools default) via the internal X-MCP-Scope header
curl -s -o /dev/null -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/mcp" || true
grep -q "smoke-scope" "$scopes_tmp" \
    || fail "X-MCP-Scope not sent to auth-bridge / wrong scope"

# 2) without Authorization, the gateway replies 401 with a Bearer
#    challenge carrying the configured scope
challenge=$(curl -s -D - -o /dev/null -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/mcp")
grep -i '^www-authenticate:' <<<"$challenge" | grep -q 'scope="smoke-scope"' \
    || fail "401 challenge missing configured scope: $challenge"

# 3) the metadata advertises the configured scope
metadata=$(curl -sf -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/.well-known/oauth-protected-resource")
grep -q '"scopes_supported":\["smoke-scope"\]' <<<"$metadata" \
    || fail "metadata scopes_supported wrong: $metadata"

# --- Upstream policy (proxied external site) ---
step "upstream: host rewritten, static header, redirects, responseHeaders"

# 1) Host rewritten to the backend origin + Authorization injected by
#    the gateway (${SMOKE_UPSTREAM_TOKEN} interpolation) + X-Strip-Me removed
echo_result=$(curl -sf -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/echo")
grep -q "\"host\": \"127.0.0.1:${PORT_BE}\"" <<<"$echo_result" \
    || fail "Upstream host not rewritten: $echo_result"
grep -q '"authorization": "Basic YmFzaWMtdG9rZW4="' <<<"$echo_result" \
    || fail "Static Authorization not injected: $echo_result"
grep -q '"strip_present": false' <<<"$echo_result" \
    || fail "X-Strip-Me (empty value) not removed: $echo_result"

# 2) absolute Location from the backend origin rewritten back to the public host
resp_redirect=$(curl -s -D - -o /dev/null -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/redirect?loc=http%3A%2F%2F127.0.0.1%3A${PORT_BE}%2Fcible%2F%3Fa%3D1")
loc=$(grep -i '^location:' <<<"$resp_redirect" | tr -d '\r' | awk '{print $2}')
[ "$loc" = "https://upstream.smoke.local/cible/?a=1" ] \
    || fail "Location not rewritten: '$loc'"

# 3) backend CSP removed + response header set
resp_page=$(curl -s -D - -o /dev/null -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/page")
grep -qi '^content-security-policy:' <<<"$resp_page" \
    && fail "Origin CSP not removed"
grep -qi '^x-gateway-smoke: upstream' <<<"$resp_page" \
    || fail "X-Gate-One-Smoke not set"

# 4) the guard script is still injected into the proxied HTML
grep_body '__cladoneAuthGuard' \
    -H "Host: upstream.smoke.local" "http://127.0.0.1:${PORT_GW}/page" \
    || fail "guard not injected into the upstream site"

# 5) HTML served gzip by the origin, client offering gzip+br (like a
#    browser): the response must arrive UNCOMPRESSED with the guard —
#    never a mangled compressed body (2026-10-17 incident:
#    Cloudflare answered brotli → unreadable page despite the 200).
grep_body 'gzip-ok' \
    -H "Host: upstream.smoke.local" \
    -H "Accept-Encoding: gzip, deflate, br, zstd" \
    "http://127.0.0.1:${PORT_GW}/gz" \
    || fail "gzip HTML not decompressed (unreadable page)"
grep_body '__cladoneAuthGuard' \
    -H "Host: upstream.smoke.local" \
    -H "Accept-Encoding: gzip, deflate, br, zstd" \
    "http://127.0.0.1:${PORT_GW}/gz" \
    || fail "guard not injected into the gzip HTML"

# 6) page > 1 MiB (old limit): injected AND served in full — never
#    truncated (2026-10-17 incident: a 6 MB book cut off at 1 MiB).
big_file=/tmp/gw-smoke-big.$$.html
big_size=$(curl -s -o "$big_file" -w '%{size_download}' \
    -H "Host: upstream.smoke.local" "http://127.0.0.1:${PORT_GW}/big")
grep -q '__cladoneAuthGuard' "$big_file" \
    || { rm -f "$big_file"; fail "guard not injected into a 1.5 MiB page"; }
[ "$big_size" -gt 1572864 ] \
    || { rm -f "$big_file"; fail "page > 1 MiB truncated ($big_size bytes received)"; }
rm -f "$big_file"

echo "SMOKE OK"
