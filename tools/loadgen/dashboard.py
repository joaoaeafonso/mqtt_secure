"""Local web dashboard for a running Lab (stdlib HTTP server, localhost only).

    GET  /                      the dashboard page
    GET  /api/state?since=T     config, metric points newer than T, change log
    POST /api/config            partial config as JSON, e.g. {"transport": {"mode": "tls"}}

The same API works from the command line:
    curl -s localhost:8088/api/config -d '{"payload": {"replay": false}}'
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from lab import Lab

PAGE = Path(__file__).with_name("dashboard.html")


def serve(lab: Lab, host: str, port: int) -> ThreadingHTTPServer:
    page = PAGE.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            url = urlparse(self.path)
            if url.path == "/":
                self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
            elif url.path == "/api/state":
                since = float(parse_qs(url.query).get("since", ["0"])[0])
                self._json(HTTPStatus.OK, lab.state(since))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/api/config":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                patch = json.loads(self.rfile.read(length) or b"{}")
                changes = lab.apply(patch)
            except (ValueError, json.JSONDecodeError) as e:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(e), "config": lab.config})
                return
            self._json(HTTPStatus.OK, {"changed": changes, "config": lab.config})

        def log_message(self, *_args) -> None:
            pass  # keep the terminal for lab events

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server
