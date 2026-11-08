#!/usr/bin/env python3
"""Minimal demo backend: shows the identity headers Gate One sends.

DEMO_TITLE renames the page, so several instances can be told apart.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import html
import os

TITLE = os.environ.get("DEMO_TITLE", "Demo backend")
PORT = int(os.environ.get("DEMO_PORT", "8080"))

HEADERS = (
    "X-Gate-One-Subject",
    "X-User-Id",
    "X-Username",
    "X-Email",
    "X-Roles",
    "X-Scopes",
    "X-Claims",
)

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; }}
  th, td {{ border: 1px solid #ccc; padding: .35rem .6rem; text-align: left; }}
  code {{ font-size: 13px; }}
</style>
</head><body><h1>{title}</h1>{table}</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming)
        if self.path.startswith("/healthz"):
            self._send(200, b'{"status":"ok"}', "application/json")
            return

        rows = []
        for name in HEADERS:
            value = self.headers.get(name)
            if value:
                rows.append(
                    "<tr><th>%s</th><td><code>%s</code></td></tr>"
                    % (html.escape(name), html.escape(value))
                )
        table = (
            "<table>%s</table>" % "".join(rows)
            if rows
            else "<p>No identity headers on this request.</p>"
        )
        page = PAGE.format(title=html.escape(TITLE), table=table).encode()
        self._send(200, page, "text/html; charset=utf-8")

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep the demo output quiet
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
