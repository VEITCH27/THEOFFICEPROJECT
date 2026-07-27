"""Daemon mode — background scheduled monitoring with drift alerts."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from sentinel.defaults import SENTINEL_DIR
from sentinel.diff import full_diff
from sentinel.incident import log_incident
from sentinel.manifest import save_snapshot, load_snapshot, list_snapshots
from sentinel.policy import evaluate_diff
from sentinel.snapshot import take_snapshot


DAEMON_PID_FILE = SENTINEL_DIR / "daemon.pid"
DAEMON_CONFIG_FILE = SENTINEL_DIR / "daemon_config.json"
DAEMON_LOG_FILE = SENTINEL_DIR / "daemon.log"
DRIFT_LOG_FILE = SENTINEL_DIR / "drift.jsonl"


# ── Configuration ────────────────────────────────────────────────────────


DEFAULT_CONFIG = {
    "interval_seconds": 3600,          # Every hour
    "baseline_snapshot": "",           # Path to baseline snapshot (empty = auto-create)
    "model_dirs": [],                  # Model working directories
    "extra_paths": [],                 # Extra paths to monitor
    "alert_on_suspicious": True,       # Alert on suspicious changes
    "alert_on_critical": True,         # Alert on critical changes
    "auto_baseline": True,            # Auto-create baseline on first run
    "notify_command": "",              # External command to run on alert
    "max_drift_records": 1000,         # Max drift log entries
}


def load_config() -> Dict:
    """Load daemon configuration."""
    config_path = DAEMON_CONFIG_FILE.expanduser()
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)
    try:
        cfg = json.loads(config_path.read_text())
        return {**DEFAULT_CONFIG, **cfg}
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(config: Dict) -> None:
    """Save daemon configuration."""
    config_path = DAEMON_CONFIG_FILE.expanduser()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))


def _log(msg: str) -> None:
    """Write a message to the daemon log file."""
    log_path = DAEMON_LOG_FILE.expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"[{timestamp}] {msg}"
    with open(log_path, "a") as f:
        f.write(line + "\n")
    print(line, file=sys.stderr)


# ── PID Management ───────────────────────────────────────────────────────


def is_running() -> bool:
    """Check if the daemon is currently running."""
    pid_path = DAEMON_PID_FILE.expanduser()
    if not pid_path.exists():
        return False
    try:
        pid = int(pid_path.read_text().strip())
        # Check if process exists
        os.kill(pid, 0)
        return True
    except (ValueError, OSError, ProcessLookupError):
        pid_path.unlink(missing_ok=True)
        return False


def write_pid() -> None:
    """Write the current PID to the PID file."""
    pid_path = DAEMON_PID_FILE.expanduser()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()))


def remove_pid() -> None:
    """Remove the PID file."""
    pid_path = DAEMON_PID_FILE.expanduser()
    pid_path.unlink(missing_ok=True)


# ── Alerting ─────────────────────────────────────────────────────────────


def _run_notify(command: str, message: str, incident_id: str) -> None:
    """Run an external notification command with the alert details."""
    if not command:
        return
    try:
        env = os.environ.copy()
        env["SENTINEL_ALERT"] = message
        env["SENTINEL_INCIDENT"] = incident_id
        subprocess.run(
            command, shell=True, capture_output=True, timeout=30, env=env,
        )
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"Notification command failed: {e}")


# ── Drift Logging ────────────────────────────────────────────────────────


def _log_drift(drift_record: Dict) -> None:
    """Append a drift record to the drift log, trimming to max size."""
    drift_path = DRIFT_LOG_FILE.expanduser()
    drift_path.parent.mkdir(parents=True, exist_ok=True)

    with open(drift_path, "a") as f:
        f.write(json.dumps(drift_record) + "\n")

    # Trim to max records
    config = load_config()
    max_records = config.get("max_drift_records", 1000)
    _trim_drift_log(drift_path, max_records)


def _trim_drift_log(path: Path, max_records: int) -> None:
    """Keep only the most recent drift records."""
    try:
        lines = path.read_text().splitlines()
        if len(lines) > max_records:
            path.write_text("\n".join(lines[-max_records:]) + "\n")
    except OSError:
        pass


# ── Main Loop ────────────────────────────────────────────────────────────


def run_daemon(interval: Optional[int] = None, once: bool = False) -> None:
    """Run the Sentinel daemon.

    Takes periodic snapshots and detects drift from baseline.

    Args:
        interval: Override check interval in seconds.
        once: Run a single check and exit (for cron integration).
    """
    config = load_config()
    config_path = DAEMON_CONFIG_FILE.expanduser()

    if interval is not None:
        config["interval_seconds"] = interval
        save_config(config)

    _log("Sentinel daemon starting")

    # Auto-create baseline if needed
    baseline_path = None
    if config.get("auto_baseline") and not config.get("baseline_snapshot"):
        _log("No baseline found — creating initial baseline snapshot")
        snapshot = take_snapshot(label="daemon_baseline")
        baseline_path = save_snapshot(snapshot, label="daemon_baseline")
        config["baseline_snapshot"] = str(baseline_path)
        save_config(config)
        _log(f"Baseline saved to {baseline_path}")

    baseline_str = config.get("baseline_snapshot", "")
    if baseline_str:
        baseline_path = Path(baseline_str)

    if not baseline_path or not baseline_path.exists():
        _log("ERROR: No baseline snapshot available. Run 'sentinel daemon init' first.")
        return

    _log(f"Using baseline: {baseline_path}")

    # Main loop
    iteration = 0
    while True:
        iteration += 1
        _log(f"Check #{iteration} starting")

        try:
            _run_check(baseline_path, config)
        except Exception as e:
            _log(f"Check failed: {e}")

        if once:
            _log("Single check complete (--once mode)")
            break

        interval = config.get("interval_seconds", 3600)
        _log(f"Next check in {interval}s")
        time.sleep(interval)


def _run_check(baseline_path: Path, config: Dict) -> None:
    """Run a single check cycle."""
    # Take current snapshot
    current = take_snapshot(
        label="daemon_check",
        extra_paths=[Path(p) for p in config.get("extra_paths", [])] if config.get("extra_paths") else None,
    )
    current_path = save_snapshot(current, label="daemon_check")
    _log(f"Snapshot: {current_path}")

    # Load baseline
    baseline = load_snapshot(baseline_path)

    # Diff
    diff_result = full_diff(baseline, current)
    policy_result = evaluate_diff(diff_result, config.get("model_dirs"))

    verdict = policy_result.get("verdict", "UNKNOWN")
    counts = policy_result.get("counts", {})
    evaluations = policy_result.get("evaluations", [])

    # Log drift if anything was found
    has_suspicious_or_critical = (
        counts.get("suspicious", 0) > 0 or counts.get("critical", 0) > 0
    )

    if has_suspicious_or_critical:
        summary = f"Drift detected: {counts.get('critical', 0)} critical, {counts.get('suspicious', 0)} suspicious changes"
        _log(f"⚠ {summary}")

        incident = log_incident(
            verdict=verdict,
            severity_counts=counts,
            pre_snapshot=baseline_path,
            post_snapshot=current_path,
            command="(daemon auto-check)",
            label="daemon_check",
            model_dirs=config.get("model_dirs", []),
            summary=summary,
            findings_count=len(evaluations),
        )

        drift_record = {
            "incident_id": incident.get("id", ""),
            "timestamp": incident.get("timestamp", ""),
            "verdict": verdict,
            "severity_counts": counts,
            "baseline": str(baseline_path),
            "snapshot": str(current_path),
            "summary": summary,
            "findings": [
                {"severity": e.get("severity"), "message": e.get("message")}
                for e in evaluations[:50]
            ],
        }
        _log_drift(drift_record)

        # Run notification command
        notify_cmd = config.get("notify_command", "")
        if notify_cmd:
            _run_notify(notify_cmd, summary, incident.get("id", ""))

        _log(f"Incident logged: {incident.get('id')}")
    else:
        _log("✓ No drift detected")

    # Also log clean checks to incident log with INFO severity
    if counts.get("info", 0) > 0:
        log_incident(
            verdict=verdict,
            severity_counts=counts,
            pre_snapshot=baseline_path,
            post_snapshot=current_path,
            command="(daemon auto-check)",
            label="daemon_check",
            model_dirs=config.get("model_dirs", []),
            summary=f"Info-level changes detected: {counts.get('info', 0)}",
            findings_count=len(evaluations),
        )


# ── Signal Handling ──────────────────────────────────────────────────────


def _signal_handler(signum, frame):
    """Handle shutdown signals."""
    _log(f"Received signal {signum}, shutting down")
    remove_pid()
    sys.exit(0)


def setup_signal_handlers() -> None:
    """Set up signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
