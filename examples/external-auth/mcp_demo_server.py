#!/usr/bin/env python3
"""Minimal MCP tool-call stand-in placed behind Envoy.

Only requests that pass ASC external authorization should reach this process.
It does not enforce policy; it records that the gated call was admitted.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse


class McpDemoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path == "/healthz":
            self._write(200, {"status": "ok", "role": "mcp-demo"})
            return
        self._write(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/mcp/v1/tools/call":
            self._write(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}
        trace = body.get("trace", body) if isinstance(body, dict) else {}
        calls = trace.get("calls", []) if isinstance(trace, dict) else []
        tools = [c.get("tool") for c in calls if isinstance(c, dict)]
        self._write(
            200,
            {
                "executed": True,
                "tools": tools,
                "note": "reached mcp-demo only after ASC ext_authz ALLOW",
            },
        )


def main() -> int:
    host = "0.0.0.0"
    port = int(__import__("os").environ.get("PORT", "8090"))
    print(f"MCP demo listening on http://{host}:{port}", flush=True)
    ThreadingHTTPServer((host, port), McpDemoHandler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
