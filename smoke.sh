#!/usr/bin/env bash
# Smoke test PWA : démarre un backend factice + la gateway avec une
# route pwa, puis vérifie injection HTML, manifest, sw.js et runtime
# workbox auto-hébergé. Utilisé par `make smoke` (à la racine).
set -euo pipefail

cd "$(dirname "$0")"

PORT_GW=3999
PORT_BE=3998

routes_tmp=$(mktemp /tmp/gw-smoke-routes.XXXX.json)
backend_tmp=$(mktemp /tmp/gw-smoke-backend.XXXX.py)
trap 'kill $GW_PID $BE_PID 2>/dev/null || true; rm -f "$routes_tmp" "$backend_tmp"' EXIT

cat > "$routes_tmp" <<EOF
{
  "routes": [
    {
      "host": "smoke.local",
      "path": "/*",
      "frontend": true,
      "backend": "http://127.0.0.1:${PORT_BE}",
      "pwa": { "enabled": true, "name": "SmokeApp" }
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

python3 "$backend_tmp" "$PORT_BE" & BE_PID=$!
./bin/gateway -config "$routes_tmp" -addr ":${PORT_GW}" & GW_PID=$!
sleep 1

fail() { echo "SMOKE FAIL: $1"; exit 1; }

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

echo "SMOKE OK"
