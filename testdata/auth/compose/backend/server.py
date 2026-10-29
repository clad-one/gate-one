#!/usr/bin/env python3
"""Local E2E backend: shows the identity headers Gate One forwards."""
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDENTITY = ("X-User-Id", "X-Username", "X-Email", "X-Roles")


class Handler(BaseHTTPRequestHandler):
    server_version = "auth-e2e-backend/1"
    sys_version = ""

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, '{"status":"ok"}', "application/json")
            return
        identity = {
            name: self.headers.get(name, "") for name in IDENTITY
        }
        forwarded = {
            "host": self.headers.get("Host", ""),
            "x-forwarded-host": self.headers.get("X-Forwarded-Host", ""),
            "x-forwarded-proto": self.headers.get("X-Forwarded-Proto", ""),
        }
        if self.path.startswith("/api"):
            self._send(200, json.dumps({
                "path": self.path,
                "forwarded": forwarded,
                "identity": identity,
            }), "application/json")
            return
        rows = "".join(
            "<li><b>%s</b>: %s</li>" % (html.escape(k), html.escape(v))
            for k, v in identity.items()
        )
        body = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<title>auth e2e backend</title></head><body>"
            "<h1>auth e2e backend</h1>"
            "<p>forwarded host: %s</p><ul>%s</ul>"
            "</body></html>"
        ) % (html.escape(forwarded["x-forwarded-host"]), rows)
        self._send(200, body, "text/html; charset=utf-8")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
