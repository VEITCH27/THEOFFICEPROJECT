"""Policy engine — classifies changes as safe, suspicious, or critical."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set

from sentinel.defaults import ALLOW_LIST_FILE, POLICY_FILE


# ── Severity Levels ──────────────────────────────────────────────────────

SEVERITY_CLEAR = "clear"
SEVERITY_INFO = "info"
SEVERITY_SUSPICIOUS = "suspicious"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {
    SEVERITY_CLEAR: 0,
    SEVERITY_INFO: 1,
    SEVERITY_SUSPICIOUS: 2,
    SEVERITY_CRITICAL: 3,
}


# ── Allow List ───────────────────────────────────────────────────────────


def _load_allowlist() -> Set[str]:
    """Load the persistent allowlist of expected-change paths."""
    path = ALLOW_LIST_FILE.expanduser()
    if not path.exists():
        return set()
    import json
    try:
        data = json.loads(path.read_text())
        return set(data.get("paths", []))
    except (json.JSONDecodeError, OSError):
        return set()


def _save_allowlist(paths: Set[str]) -> None:
    """Save the allowlist to disk."""
    allow_path = ALLOW_LIST_FILE.expanduser()
    allow_path.parent.mkdir(parents=True, exist_ok=True)
    import json
    allow_path.write_text(json.dumps({"paths": sorted(paths)}, indent=2))


def add_to_allowlist(path: str) -> None:
    """Add a path to the persistent allowlist."""
    paths = _load_allowlist()
    paths.add(path)
    _save_allowlist(paths)


def remove_from_allowlist(path: str) -> None:
    """Remove a path from the persistent allowlist."""
    paths = _load_allowlist()
    paths.discard(path)
    _save_allowlist(paths)


def is_allowlisted(path: str) -> bool:
    """Check if a path is on the allowlist."""
    allowlisted = _load_allowlist()
    return path in allowlisted


# ── Policy Evaluation ────────────────────────────────────────────────────


def _load_policy() -> Dict:
    """Load custom policy overrides."""
    path = POLICY_FILE.expanduser()
    if not path.exists():
        return {}
    import json
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _is_model_working_dir(path: str, model_dirs: List[str]) -> bool:
    """Check if a path is inside any of the declared model working directories."""
    p = Path(path).resolve()
    for md in model_dirs:
        md_path = Path(md).resolve()
        if md_path in p.parents or md_path == p:
            return True
    return False


def evaluate_file_change(
    change: Dict,
    model_dirs: Optional[List[str]] = None,
) -> Dict:
    """Evaluate the severity of a file change.

    Returns a dict with severity, summary, and action recommendation.
    """
    path = change.get("path", "")
    category = change.get("category", "extra")
    volatile = change.get("volatile", False)
    change_type = "added" if "sha256" in change and "pre_sha256" not in change else \
                  "removed" if "sha256" in change and "post_sha256" not in change else \
                  "modified"
    # Actually let's determine type from which dict we're in:
    # This is called from report.py which will pass the type

    return _evaluate(path, category, volatile, change.get("change_type", "modified"), model_dirs)


def _evaluate(
    path: str,
    category: str,
    volatile: bool,
    change_type: str,
    model_dirs: Optional[List[str]] = None,
) -> Dict:
    """Core evaluation logic."""
    model_dirs = model_dirs or []

    # Allowlisted paths are always OK
    if is_allowlisted(path):
        return {
            "severity": SEVERITY_CLEAR,
            "label": "allowlisted",
            "message": f"Change to allowlisted path: {path}",
            "action": "ignore",
        }

    # Inside model working dir — low severity
    if _is_model_working_dir(path, model_dirs):
        return {
            "severity": SEVERITY_INFO if change_type in ("added", "modified") else SEVERITY_SUSPICIOUS,
            "label": "model_working_dir",
            "message": f"{change_type.capitalize()} inside model working directory: {path}",
            "action": "review",
        }

    # Volatile paths (temp, cache, logs) — informational
    if volatile:
        return {
            "severity": SEVERITY_INFO,
            "label": "volatile_path",
            "message": f"{change_type.capitalize()} in volatile location: {path}",
            "action": "info",
        }

    # Critical paths are always critical
    if category == "critical":
        return {
            "severity": SEVERITY_CRITICAL,
            "label": "critical_system_change",
            "message": f"{change_type.capitalize()} to critical system path: {path}",
            "action": "investigate",
        }

    # Suspicious paths
    if category == "suspicious":
        return {
            "severity": SEVERITY_SUSPICIOUS,
            "label": "suspicious_change",
            "message": f"{change_type.capitalize()} to monitored config path: {path}",
            "action": "review",
        }

    # Extra paths — default to info
    return {
        "severity": SEVERITY_INFO,
        "label": "extra_path_change",
        "message": f"{change_type.capitalize()} to monitored path: {path}",
        "action": "review",
    }


def evaluate_diff(diff: Dict, model_dirs: Optional[List[str]] = None) -> Dict:
    """Run policy evaluation over an entire diff result.

    Returns a categorized summary with severity counts.
    """
    model_dirs = model_dirs or []
    evaluations = []

    # Evaluate file changes
    for change_type in ("added", "removed", "modified"):
        for change in diff.get("files", {}).get(change_type, []):
            ev = _evaluate(
                change["path"],
                change.get("category", "extra"),
                change.get("volatile", False),
                change_type,
                model_dirs,
            )
            evaluations.append({**ev, "path": change["path"], "change_type": change_type})

    # Process changes get a default evaluation
    for proc in diff.get("processes", {}).get("new", []):
        evaluations.append({
            "severity": SEVERITY_INFO,
            "label": "new_process",
            "message": f"New process started: {proc.get('name', '?')} (PID {proc.get('pid', '?')})",
            "action": "info",
            "path": f"/proc/{proc.get('pid', '?')}",
            "change_type": "new_process",
        })

    for proc in diff.get("processes", {}).get("gone", []):
        evaluations.append({
            "severity": SEVERITY_INFO,
            "label": "process_ended",
            "message": f"Process ended: {proc.get('name', '?')} (was PID {proc.get('pid', '?')})",
            "action": "info",
            "path": "",
            "change_type": "process_ended",
        })

    # Service changes
    for svc in diff.get("services", {}).get("changed", []):
        evaluations.append({
            "severity": SEVERITY_SUSPICIOUS,
            "label": "service_state_change",
            "message": f"Service '{svc.get('unit', '?')}' changed state: {svc.get('pre', '?')} → {svc.get('post', '?')}",
            "action": "review",
            "path": "",
            "change_type": "service_change",
        })

    # Cron changes
    for cron_change in diff.get("cron", {}).get("changes", []):
        if cron_change.get("type") == "system_cron":
            evaluations.append({
                "severity": SEVERITY_CRITICAL,
                "label": "cron_change",
                "message": f"System cron file changed: {cron_change.get('file', '?')}",
                "action": "investigate",
                "path": cron_change.get("file", ""),
                "change_type": "cron_change",
            })
        else:
            evaluations.append({
                "severity": SEVERITY_SUSPICIOUS,
                "label": "user_crontab_change",
                "message": f"User crontab changed: {cron_change.get('user', '?')}",
                "action": "review",
                "path": "",
                "change_type": "cron_change",
            })

    # Network changes
    net = diff.get("network", {})
    for key, label in [
        ("interfaces_changed", "Network interfaces"),
        ("routing_changed", "Routing table"),
        ("dns_changed", "DNS configuration"),
        ("listening_changed", "Listening ports"),
        ("firewall_changed", "Firewall rules"),
    ]:
        if net.get(key):
            evaluations.append({
                "severity": SEVERITY_CRITICAL if key in ("firewall_changed", "interfaces_changed", "listening_changed")
                else SEVERITY_SUSPICIOUS,
                "label": "network_change",
                "message": f"{label} changed",
                "action": "investigate" if key in ("firewall_changed", "interfaces_changed") else "review",
                "path": "",
                "change_type": "network_change",
            })

    # Kernel changes
    kern = diff.get("kernel", {})
    if kern.get("modules_changed"):
        evaluations.append({
            "severity": SEVERITY_CRITICAL,
            "label": "kernel_modules_changed",
            "message": "Kernel modules changed — new modules loaded or unloaded",
            "action": "investigate",
            "path": "",
            "change_type": "kernel_change",
        })

    # Count by severity
    counts = {SEVERITY_CLEAR: 0, SEVERITY_INFO: 0, SEVERITY_SUSPICIOUS: 0, SEVERITY_CRITICAL: 0}
    for ev in evaluations:
        sev = ev.get("severity", SEVERITY_INFO)
        counts[sev] = counts.get(sev, 0) + 1

    # Determine overall verdict
    if counts[SEVERITY_CRITICAL] > 0:
        verdict = "FAIL — critical changes detected"
    elif counts[SEVERITY_SUSPICIOUS] > 0:
        verdict = "WARNING — suspicious changes detected"
    elif counts[SEVERITY_INFO] > 0:
        verdict = "INFO — non-critical changes detected"
    else:
        verdict = "PASS — no changes detected"

    return {
        "verdict": verdict,
        "counts": counts,
        "evaluations": evaluations,
    }
