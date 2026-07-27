"""Dashboard — local web-based GUI for Sentinel."""

from __future__ import annotations

import json
import os
import signal
import sys
import webbrowser
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict

from sentinel.defaults import SENTINEL_DIR
from sentinel.incident import list_incidents, get_incident_stats
from sentinel.manifest import list_snapshots, load_snapshot

# ── Locate static files ────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "dashboard_static"

def _read_static(filename: str) -> str:
    """Read a static file from the dashboard_static directory."""
    path = STATIC_DIR / filename
    if path.exists():
        return path.read_text()
    return f"/* {filename} not found */"


# ── HTML Template ───────────────────────────────────────────────────────


def _get_html() -> str:
    """Render the dashboard HTML page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel Dashboard</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>

<div class="header-row">
  <div>
    <h1>🛡 Sentinel</h1>
    <div class="subtitle">AI Model Runtime Integrity Dashboard</div>
  </div>
  <div class="daemon-indicator" id="daemon-indicator">
    <span class="daemon-dot daemon-stopped"></span> Checking...
  </div>
</div>

<div class="nav">
  <a data-view="overview" class="active" onclick="showView('overview')">Overview</a>
  <a data-view="incidents" onclick="showView('incidents')">Incidents</a>
  <a data-view="snapshots" onclick="showView('snapshots')">Snapshots</a>
</div>

<div id="overview-view"><div id="overview-content"></div></div>
<div id="incidents-view" style="display:none"><div id="incidents-content"></div></div>
<div id="snapshots-view" style="display:none"><div id="snapshots-content"></div></div>

<!-- Modal -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <span class="modal-close" onclick="closeModal()">&times;</span>
    <h2 id="modal-title"></h2>
    <div id="modal-body"></div>
  </div>
</div>

<script src="/app.js"></script>
</body>
</html>"""


# ── API Handler ─────────────────────────────────────────────────────────


class SentinelAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler that serves the dashboard and API endpoints."""

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging

    def _send_json(self, data: Dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _send_text(self, text: str, content_type: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(text.encode())

    def do_GET(self):
        path = self.path.rstrip("/") or "/"

        if path == "/" or path == "/index.html":
            self._send_text(_get_html(), "text/html; charset=utf-8")
        elif path == "/styles.css":
            self._send_text(_read_static("styles.css"), "text/css; charset=utf-8")
        elif path == "/app.js":
            self._send_text(_read_static("app.js"), "application/javascript; charset=utf-8")

        # ── API Endpoints ────────────────────────────────────────────
        elif path == "/api/stats":
            self._send_json(self._get_stats())
        elif path == "/api/incidents":
            self._send_json({"incidents": list_incidents(limit=200)})
        elif path == "/api/incidents/stats":
            self._send_json(get_incident_stats())
        elif path == "/api/snapshots":
            self._send_json(self._get_snapshots_data())

        elif path.startswith("/api/snapshot/"):
            snap_path = path.replace("/api/snapshot/", "", 1)
            try:
                data = load_snapshot(Path(snap_path))
                self._send_json({"snapshot": data})
            except Exception as e:
                self._send_json({"error": str(e)}, 404)

        elif path == "/api/daemon/status":
            from sentinel.daemon import is_running, load_config
            running = is_running()
            config = load_config() if running else {}
            self._send_json({"running": running, "config": config})

        else:
            self._send_json({"error": "Not found"}, 404)

    def _get_stats(self) -> Dict:
        stats = get_incident_stats()
        snaps = list_snapshots()
        from sentinel.daemon import is_running
        return {
            "total_incidents": stats.get("total", 0),
            "total_snapshots": len(snaps),
            "verdict_summary": stats.get("verdict_summary", {}),
            "daemon_running": is_running(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    def _get_snapshots_data(self) -> Dict:
        snaps = list_snapshots()
        result = []
        for s in snaps[:50]:
            try:
                data = load_snapshot(s)
                meta = data.get("meta", {})
                files = data.get("files", {})
                file_count = sum(len(v) for v in files.values() if isinstance(v, dict))
                snapshot_entry = {
                    "path": str(s),
                    "label": meta.get("label", ""),
                    "timestamp": meta.get("timestamp", ""),
                    "hostname": meta.get("hostname", ""),
                    "manifest_hash": meta.get("manifest_hash", "")[:16],
                    "file_count": file_count,
                    "process_count": len(data.get("processes", {})),
                    "has_signature": bool(meta.get("signature")),
                }
                if meta.get("signature"):
                    snapshot_entry["signature"] = meta["signature"]
                result.append(snapshot_entry)
            except Exception:
                pass
        return {"snapshots": result}


# ── Server ──────────────────────────────────────────────────────────────


DEFAULT_PORT = 8099


def start_dashboard(port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    """Start the Sentinel dashboard server."""
    server = HTTPServer(("127.0.0.1", port), SentinelAPIHandler)
    url = f"http://127.0.0.1:{port}"

    print(f"  Sentinel Dashboard: {url}", file=sys.stderr)
    print(f"  Press Ctrl+C to stop", file=sys.stderr)

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def _handler(signum, frame):
        print("\n  Shutting down dashboard...", file=sys.stderr)
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down dashboard...", file=sys.stderr)
        server.shutdown()
