"""Incident log — persistent audit trail of every Sentinel run."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from sentinel.defaults import SENTINEL_DIR


INCIDENT_LOG = SENTINEL_DIR / "incidents.jsonl"
INCIDENT_INDEX = SENTINEL_DIR / "incidents_index.json"


# ── Incident Record ──────────────────────────────────────────────────────


def log_incident(
    verdict: str,
    severity_counts: Dict[str, int],
    pre_snapshot: Optional[Path] = None,
    post_snapshot: Optional[Path] = None,
    command: str = "",
    label: str = "",
    model_dirs: Optional[List[str]] = None,
    summary: str = "",
    findings_count: int = 0,
) -> Dict:
    """Log an incident to the persistent JSON Lines audit trail.

    Returns the incident record that was logged.
    """
    record = {
        "id": _next_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "severity_counts": severity_counts,
        "pre_snapshot": str(pre_snapshot) if pre_snapshot else "",
        "post_snapshot": str(post_snapshot) if post_snapshot else "",
        "command": command,
        "label": label,
        "model_dirs": model_dirs or [],
        "summary": summary,
        "findings_count": findings_count,
    }

    log_path = INCIDENT_LOG.expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "a") as f:
        f.write(json.dumps(record) + "\n")

    _rebuild_index()
    return record


def _next_id() -> str:
    """Generate the next incident ID."""
    log_path = INCIDENT_LOG.expanduser()
    if not log_path.exists():
        return "INC-0001"

    count = 0
    try:
        with open(log_path) as f:
            for _ in f:
                count += 1
    except OSError:
        pass

    return f"INC-{count + 1:04d}"


def _rebuild_index() -> None:
    """Rebuild the incident index file for fast lookups."""
    log_path = INCIDENT_LOG.expanduser()
    if not log_path.exists():
        return

    index_path = INCIDENT_INDEX.expanduser()
    incidents = list_incidents()

    index = {
        "total": len(incidents),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "verdict_summary": _count_verdicts(incidents),
        "recent": incidents[:20],  # Last 20 for quick display
    }

    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(index, indent=2))


def _count_verdicts(incidents: List[Dict]) -> Dict[str, int]:
    """Count incidents by verdict type."""
    counts = {}
    for inc in incidents:
        v = inc.get("verdict", "UNKNOWN")
        # Extract first word: "PASS — no changes" -> "PASS"
        short = v.split("—")[0].split(" ")[0].strip()
        counts[short] = counts.get(short, 0) + 1
    return counts


# ── Querying ─────────────────────────────────────────────────────────────


def list_incidents(limit: int = 100, offset: int = 0) -> List[Dict]:
    """List incidents from the log, newest first."""
    log_path = INCIDENT_LOG.expanduser()
    if not log_path.exists():
        return []

    incidents = []
    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        incidents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        return []

    # Reverse so newest is first
    incidents.reverse()
    return incidents[offset:offset + limit]


def get_incident(incident_id: str) -> Optional[Dict]:
    """Get a specific incident by ID."""
    incidents = list_incidents(limit=10000)
    for inc in incidents:
        if inc.get("id") == incident_id:
            return inc
    return None


def get_incident_stats() -> Dict:
    """Get summary statistics from the incident log."""
    index_path = INCIDENT_INDEX.expanduser()
    if index_path.exists():
        try:
            return json.loads(index_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    # Rebuild if index is missing
    incidents = list_incidents(limit=10000)
    stats = {
        "total": len(incidents),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "verdict_summary": _count_verdicts(incidents),
        "recent": incidents[:20],
    }
    return stats


def get_log_path() -> Path:
    """Get the path to the incident log file."""
    return INCIDENT_LOG.expanduser()


def export_incidents(format: str = "json") -> str:
    """Export the full incident log."""
    if format == "json":
        return json.dumps(list_incidents(limit=10000), indent=2)
    elif format == "lines":
        log_path = INCIDENT_LOG.expanduser()
        if log_path.exists():
            return log_path.read_text()
        return ""
    else:
        incidents = list_incidents(limit=10000)
        lines = ["# Sentinel Incident Log", f"# Total: {len(incidents)}", ""]
        for inc in incidents:
            lines.append(
                f"{inc.get('id', '?'):<12} "
                f"{inc.get('timestamp', '?'):<30} "
                f"{inc.get('verdict', '?'):<40}"
            )
        return "\n".join(lines)
