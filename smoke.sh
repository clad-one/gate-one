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
          "set": {"X-Gateway-Smoke": "upstream"}
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
            b = b'<html><head><title>smoke</title></head><body>ok</body></html>'
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
        elif u.path == '/page':
            b = b'<html><head><title>upstream smoke</title></head><body>x</body></html>'
            self._send(200, 'text/html; charset=utf-8', b, extra={
                'Content-Security-Policy': "default-src 'self'"})
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
# SMOKE_UPSTREAM_TOKEN : lu par la gateway au chargement (interpolation
# ${...} de la policy upstream) — exactement comme en production.
# -authBridge : la gateway doit interroger le STUB local (sans flag,
# elle appellerait le nom de service Docker auth-bridge:3000).
SMOKE_UPSTREAM_TOKEN=YmFzaWMtdG9rZW4= \
  ./bin/gateway -config "$routes_tmp" -addr ":${PORT_GW}" \
    -authBridge "http://127.0.0.1:${PORT_AB}" > "$gw_log" 2>&1 & GW_PID=$!

# debug : les 3 services doivent écouter — attente robuste (un simple
# `sleep 1` est racy sous charge, et set -e + exec + /dev/tcp dans un
# if isolé tue le script en silence ; on passe par une fonction avec
# retry, appelée en || pour désarmer set -e).
wait_port() {
  local port=$1 name=$2 i
  for i in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "SMOKE FAIL: ${name} sur :${port} n'écoute pas" >&2
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

# grep_body : match dans un corps ENTIÈREMENT lu d'abord. Jamais de
# `curl | grep -q` en tête de pipe : grep -q sort au premier match →
# SIGPIPE aléatoire sur curl → pipefail → check floppant selon le
# scheduling (corps ~28 Ko avec la garde : course fréquente).
grep_body() {
  local pattern=$1; shift
  local body
  body=$(curl -sf "$@") || return 1
  grep -q "$pattern" <<<"$body"
}

step "injection HTML"
grep_body '<link rel="manifest" href="/__gateway_pwa/manifest.json">' \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/" \
    || fail "manifest link not injected in HTML"

grep_body '"name": "SmokeApp"' \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/manifest.json" \
    || fail "manifest not served / wrong name"

grep_body "modulePathPrefix: '/__gateway_pwa/workbox/'" \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/sw.js" \
    || fail "sw.js not self-hosted"

grep_body "workbox" \
    -H "Host: smoke.local" "http://127.0.0.1:${PORT_GW}/__gateway_pwa/workbox/workbox-sw.js" \
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
    "http://127.0.0.1:${PORT_GW}/mcp")
grep -i '^www-authenticate:' <<<"$challenge" | grep -q 'scope="smoke-scope"' \
    || fail "401 challenge missing configured scope: $challenge"

# 3) la metadata annonce le scope configuré
metadata=$(curl -sf -H "Host: mcp.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/.well-known/oauth-protected-resource")
grep -q '"scopes_supported":\["smoke-scope"\]' <<<"$metadata" \
    || fail "metadata scopes_supported wrong: $metadata"

# --- Policy upstream (site externe proxifié) ---
step "upstream : Host réécrit, header statique, redirects, responseHeaders"

# 1) Host réécrit vers l'origine backend + Authorization injectée par
#    la gateway (interpolation ${SMOKE_UPSTREAM_TOKEN}) + X-Strip-Me retiré
echo_result=$(curl -sf -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/echo")
grep -q "\"host\": \"127.0.0.1:${PORT_BE}\"" <<<"$echo_result" \
    || fail "Host upstream non réécrit: $echo_result"
grep -q '"authorization": "Basic YmFzaWMtdG9rZW4="' <<<"$echo_result" \
    || fail "Authorization statique non injectée: $echo_result"
grep -q '"strip_present": false' <<<"$echo_result" \
    || fail "X-Strip-Me (valeur vide) non retiré: $echo_result"

# 2) Location absolue de l'origine backend ramenée au host public
resp_redirect=$(curl -s -D - -o /dev/null -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/redirect?loc=http%3A%2F%2F127.0.0.1%3A${PORT_BE}%2Fcible%2F%3Fa%3D1")
loc=$(grep -i '^location:' <<<"$resp_redirect" | tr -d '\r' | awk '{print $2}')
[ "$loc" = "https://upstream.smoke.local/cible/?a=1" ] \
    || fail "Location non réécrite: '$loc'"

# 3) CSP du backend retiré + en-tête de réponse posé
resp_page=$(curl -s -D - -o /dev/null -H "Host: upstream.smoke.local" \
    "http://127.0.0.1:${PORT_GW}/page")
grep -qi '^content-security-policy:' <<<"$resp_page" \
    && fail "CSP d'origine non retiré"
grep -qi '^x-gateway-smoke: upstream' <<<"$resp_page" \
    || fail "X-Gateway-Smoke non posé"

# 4) le script de garde reste injecté sur le HTML proxifié
grep_body '__cladoneAuthGuard' \
    -H "Host: upstream.smoke.local" "http://127.0.0.1:${PORT_GW}/page" \
    || fail "garde non injectée sur le site upstream"

# 5) HTML servi gzip par l'origine, client qui offre gzip+br (comme
#    un navigateur) : la réponse doit arriver EN CLAIR avec la garde —
#    jamais un corps compressé manipulé (incident 2026-10-17 :
#    Cloudflare répondait brotli → page illisible malgré le 200).
grep_body 'gzip-ok' \
    -H "Host: upstream.smoke.local" \
    -H "Accept-Encoding: gzip, deflate, br, zstd" \
    "http://127.0.0.1:${PORT_GW}/gz" \
    || fail "HTML gzip non décompressé (page illisible)"
grep_body '__cladoneAuthGuard' \
    -H "Host: upstream.smoke.local" \
    -H "Accept-Encoding: gzip, deflate, br, zstd" \
    "http://127.0.0.1:${PORT_GW}/gz" \
    || fail "garde non injectée sur le HTML gzip"

echo "SMOKE OK"
