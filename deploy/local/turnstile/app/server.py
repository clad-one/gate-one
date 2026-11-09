#!/usr/bin/env python3
"""Tiny backend for the Turnstile demo: one page and one API call.

The page is a normal HTML document; the button posts JSON to
/api/submit. In "api" mode the page is public and only the API is
gated; in "gate" mode the whole page is gated.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("TURNSTILE_DEMO_MODE", "gate")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(
    os.environ.get("TURNSTILE_DEMO_PORT", "8081")
)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Turnstile demo</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
background:#e5eae4;color:#1c1f23}
main{width:min(92vw,560px);padding:26px;background:#fff;border:1px solid #cfd6dd;
border-radius:14px}
h1{font-size:20px;margin:0 0 6px;color:#2a5f3f}
p{margin:0 0 12px;color:#5c6470}
textarea{width:100%;box-sizing:border-box;min-height:88px;padding:10px;
border:1px solid #cfd6dd;border-radius:8px;font:inherit}
button{margin-top:10px;padding:9px 16px;border:0;border-radius:8px;
background:#4a7c59;color:#fff;font:inherit;font-weight:600;cursor:pointer}
pre{margin:14px 0 0;padding:10px;background:#f4f6f4;border-radius:8px;
white-space:pre-wrap;word-break:break-word;font-size:13px}
code{background:#f4f6f4;padding:1px 5px;border-radius:4px}
</style>
</head>
<body>
<main>
<h1>Turnstile demo</h1>
<p id="mode"></p>
<textarea id="msg" placeholder="Type a message and submit it.">hello from the demo</textarea>
<button id="send">Submit the action</button>
<pre id="out">No request sent yet.</pre>
<p><small>Current mode: <code>%MODE%</code>. In <code>gate</code> the whole
page is challenged; in <code>api</code> the page is public and the first
action triggers the challenge (or is replayed after the background
check).</small></p>
</main>
<script>
document.getElementById("mode").textContent =
  location.pathname === "/" && %MODE_JSON% === "api"
    ? "The page is public. Only the action (/api/*) is protected."
    : "The page is served after the anti-robot verification.";
document.getElementById("send").addEventListener("click", async function () {
  var out = document.getElementById("out");
  out.textContent = "Sending…";
  try {
    var res = await fetch("/api/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: document.getElementById("msg").value })
    });
    var body = await res.text();
    out.textContent = res.status + " " + res.statusText + "\\n" + body;
  } catch (e) {
    out.textContent = "Request failed: " + e;
  }
});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "turnstile-demo"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, b'{"status":"ok"}', "application/json")
            return
        if self.path in ("/", "/index.html"):
            page = (
                PAGE.replace("%MODE%", MODE)
                .replace("%MODE_JSON%", json.dumps(MODE))
                .encode()
            )
            self._send(200, page, "text/html; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        if self.path != "/api/submit":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", "replace")}
        body = json.dumps(
            {
                "ok": True,
                "mode": MODE,
                "received": payload,
                "verifiedBy": "gate-one + Cloudflare Turnstile",
            }
        ).encode()
        self._send(200, body, "application/json")

    def log_message(self, fmt: str, *args) -> None:
        print("backend:", fmt % args, flush=True)


if __name__ == "__main__":
    print(f"turnstile demo backend: mode={MODE} on :{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
