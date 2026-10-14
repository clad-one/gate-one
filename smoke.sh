#!/usr/bin/env bash
# Smoke test gateway : démarre un backend factice + une passerelle avec
# une route pwa et une route MCP authentifiée, puis vérifie injection
# HTML, manifest, sw.js, runtime workbox auto-hébergé, et le circuit
# MCP (scope configuré, header X-MCP-Scope vers auth-bridge factice,
# challenge 401, metadata). Utilisé par `make smoke` (à la racine).
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
# le gw_log est conservé après le run (diagnostic) : /tmp/gw-smoke-gwlog.*
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
    }
  ]
}
EOF

cat > "$backend_tmp" <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            b = b'<html><head><title>smoke</title></head><body>ok</body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        else:
            self.send_response(404)
            self.end_headers()


HTTPServer(('127.0.0.1', int(__import__('sys').argv[1])), H).serve_forever()
EOF

# auth-bridge factice : note le header X-MCP-Scope reçu et répond
# toujours 401 — la gateway doit transformer ça en challenge Bearer
# portant le scope configuré.
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
./bin/gateway -config "$routes_tmp" -addr ":${PORT_GW}" > "$gw_log" 2>&1 & GW_PID=$!
sleep 1

# debug : les 3 services doivent écouter
for p in "$PORT_BE" "$PORT_AB" "$PORT_GW"; do
  if ! (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then
    echo "SMOKE FAIL: service sur :$p n'écoute pas" >&2
    exit 1
  fi
  exec 3>&- 2>/dev/null || true
done

fail() {
  echo "SMOKE FAIL: $1" >&2
  echo "--- gateway log ---" >&2
  cat "${gw_log:-/dev/null}" >&2 || true
  exit 1
}

step() { echo "… $1" >&2; }

step "injection HTML"
curl -sf -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/" \
    | grep -q '<link rel="manifest" href="/__gateway_pwa/manifest.json">' \
    || fail "manifest link not injected in HTML"

curl -sf -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/manifest.json" \
    | grep -q '"name": "SmokeApp"' \
    || fail "manifest not served / wrong name"

curl -sf -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/sw.js" \
    | grep -q "modulePathPrefix: '/__gateway_pwa/workbox/'" \
    || fail "sw.js not self-hosted"

curl -sf -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/workbox/workbox-sw.js" \
    | grep -q "workbox" \
    || fail "embedded workbox runtime not served"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: smoke.local" \
    "http://127.0.0.1:${PORT_GW}/__gateway_pwa/workbox/../pwa.go")
[ "$code" = "404" ] || fail "path traversal not blocked (got $code)"

# --- Circuit MCP ---
step "circuit MCP (X-MCP-Scope → auth-bridge)"
# 1) auth-bridge factice reçoit le scope configuré de la route (pas le
#    défaut mcp-tools) via le header interne X-MCP-Scope
curl -s -o /dev/null -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/mcp" || true
grep -q "smoke-scope" "$scopes_tmp" \
    || fail "X-MCP-Scope not sent to auth-bridge / wrong scope"

# 2) sans Authorization, la gateway répond 401 avec un challenge Bearer
#    portant le scope configuré
challenge=$(curl -s -D - -o /dev/null -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/mcp" \
    | grep -i '^www-authenticate:' | tr -d '\r')
echo "$challenge" | grep -q 'scope="smoke-scope"' \
    || fail "401 challenge missing configured scope: $challenge"

# 3) la metadata annonce le scope configuré
metadata=$(curl -sf -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/.well-known/oauth-protected-resource")
echo "$metadata" | grep -q '"scopes_supported":\["smoke-scope"\]' \
    || fail "metadata scopes_supported wrong: $metadata"

echo "SMOKE OK"
