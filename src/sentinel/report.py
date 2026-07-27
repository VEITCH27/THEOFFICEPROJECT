"""Reporting — formats policy evaluation results for terminal and JSON output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List, Optional

from sentinel.policy import SEVERITY_ORDER, SEVERITY_CRITICAL, SEVERITY_SUSPICIOUS


# ── ANSI colors (no dependencies required) ───────────────────────────────

class Style:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    RESET = "\033[0m"


def _severity_color(severity: str) -> str:
    return {
        "clear": Style.GREEN,
        "info": Style.CYAN,
        "suspicious": Style.YELLOW,
        "critical": Style.RED,
    }.get(severity, Style.RESET)


def _severity_badge(severity: str) -> str:
    labels = {
        "clear": "  CLEAR  ",
        "info": "  INFO   ",
        "suspicious": "SUSPICIOUS",
        "critical": "CRITICAL ",
    }
    color = _severity_color(severity)
    return f"{color}{Style.BOLD}{labels.get(severity, 'UNKNOWN')}{Style.RESET}"


def print_terminal_report(
    diff: Dict,
    evaluation: Dict,
    model_dirs: Optional[List[str]] = None,
) -> str:
    """Generate a colored terminal report string."""
    lines = []
    lines.append("")
    lines.append(f"{Style.BOLD}{'=' * 70}{Style.RESET}")
    lines.append(f"{Style.BOLD}  SENTINEL — AI Model Runtime Integrity Report{Style.RESET}")
    lines.append(f"{Style.BOLD}{'=' * 70}{Style.RESET}")
    lines.append("")

    # Summary header
    pre_label = diff.get("pre_label", "pre")
    post_label = diff.get("post_label", "post")
    pre_ts = diff.get("pre_timestamp", "?")
    post_ts = diff.get("post_timestamp", "?")
    lines.append(f"  {Style.DIM}Baseline:{Style.RESET}  {pre_label} ({pre_ts})")
    lines.append(f"  {Style.DIM}Check:   {Style.RESET}  {post_label} ({post_ts})")
    if model_dirs:
        lines.append(f"  {Style.DIM}Model:   {Style.RESET}  {', '.join(model_dirs)}")

    # Overall verdict
    lines.append("")
    verdict = evaluation.get("verdict", "UNKNOWN")
    if verdict.startswith("PASS"):
        lines.append(f"  {Style.GREEN}{Style.BOLD}✓ {verdict}{Style.RESET}")
    elif verdict.startswith("INFO"):
        lines.append(f"  {Style.BLUE}{Style.BOLD}ℹ {verdict}{Style.RESET}")
    elif verdict.startswith("WARNING"):
        lines.append(f"  {Style.YELLOW}{Style.BOLD}⚠ {verdict}{Style.RESET}")
    else:
        lines.append(f"  {Style.RED}{Style.BOLD}✗ {verdict}{Style.RESET}")

    # Severity counts
    counts = evaluation.get("counts", {})
    lines.append("")
    lines.append(f"  {Style.DIM}Severity breakdown:{Style.RESET}")
    labels = [
        ("critical", "Critical"),
        ("suspicious", "Suspicious"),
        ("info", "Info"),
        ("clear", "Clear"),
    ]
    for key, label in labels:
        c = counts.get(key, 0)
        color = _severity_color(key)
        lines.append(f"    {color}{Style.BOLD}{c:>4}{Style.RESET}  {label}")

    # Manifest integrity
    if diff.get("manifest_hash_match", True) is False:
        lines.append("")
        lines.append(f"  {Style.YELLOW}{Style.BOLD}⚠ Manifest content hash changed!{Style.RESET}")

    # Impact summary
    files_diff = diff.get("files", {})
    added_count = len(files_diff.get("added", []))
    removed_count = len(files_diff.get("removed", []))
    modified_count = len(files_diff.get("modified", []))
    unchanged_count = files_diff.get("unchanged_count", 0)
    lines.append("")
    lines.append(f"  {Style.DIM}File summary:{Style.RESET}")
    lines.append(f"    {Style.GREEN}{added_count:>4} added{Style.RESET}  "
                 f"{Style.RED}{removed_count:>4} removed{Style.RESET}  "
                 f"{Style.YELLOW}{modified_count:>4} modified{Style.RESET}  "
                 f"{Style.GRAY}{unchanged_count:>4} unchanged{Style.RESET}")

    proc_diff = diff.get("processes", {})
    lines.append(f"  {Style.DIM}Processes:{Style.RESET}    "
                 f"{Style.GREEN}{proc_diff.get('new_count', 0):>4} new{Style.RESET}  "
                 f"{Style.RED}{proc_diff.get('gone_count', 0):>4} ended{Style.RESET}")

    svc_diff = diff.get("services", {})
    lines.append(f"  {Style.DIM}Services:{Style.RESET}     "
                 f"{Style.YELLOW}{svc_diff.get('changed_count', 0):>4} changed{Style.RESET}")

    cron_diff = diff.get("cron", {})
    lines.append(f"  {Style.DIM}Cron:{Style.RESET}         "
                 f"{Style.YELLOW}{cron_diff.get('change_count', 0):>4} changes{Style.RESET}")

    # Network changes
    net_changes = [k for k, v in diff.get("network", {}).items() if v]
    if net_changes:
        lines.append(f"  {Style.DIM}Network:{Style.RESET}      "
                     f"{Style.YELLOW}{len(net_changes)} section(s) changed{Style.RESET}")

    # Detailed findings
    evaluations = evaluation.get("evaluations", [])
    critical_evals = [e for e in evaluations if e.get("severity") == SEVERITY_CRITICAL]
    suspicious_evals = [e for e in evaluations if e.get("severity") == SEVERITY_SUSPICIOUS]

    if critical_evals:
        lines.append("")
        lines.append(f"  {Style.RED}{Style.BOLD}── Critical Findings ──{Style.RESET}")
        for ev in critical_evals:
            lines.append(f"  {_severity_badge('critical')}  {ev.get('message', '')}")
            if ev.get("path"):
                lines.append(f"          {Style.DIM}{ev.get('path')}{Style.RESET}")

    if suspicious_evals:
        lines.append("")
        lines.append(f"  {Style.YELLOW}{Style.BOLD}── Suspicious Findings ──{Style.RESET}")
        for ev in suspicious_evals:
            lines.append(f"  {_severity_badge('suspicious')}  {ev.get('message', '')}")
            if ev.get("path"):
                lines.append(f"          {Style.DIM}{ev.get('path')}{Style.RESET}")

    info_evals = [e for e in evaluations if e.get("severity") not in (SEVERITY_CRITICAL, SEVERITY_SUSPICIOUS)]
    if info_evals:
        lines.append("")
        lines.append(f"  {Style.DIM}── Info ({len(info_evals)} entries) ──{Style.RESET}")
        # Show first 10 only to keep output manageable
        for ev in info_evals[:10]:
            lines.append(f"    ℹ {ev.get('message', '')}")
        if len(info_evals) > 10:
            lines.append(f"    {Style.GRAY}... and {len(info_evals) - 10} more{Style.RESET}")

    lines.append("")
    lines.append(f"{Style.BOLD}{'=' * 70}{Style.RESET}")
    lines.append("")

    return "\n".join(lines)


def json_report(diff: Dict, evaluation: Dict) -> str:
    """Generate a JSON report string."""
    report = {
        "report_type": "sentinel_integrity_report",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "diff": diff,
        "evaluation": {
            "verdict": evaluation.get("verdict"),
            "severity_counts": evaluation.get("counts"),
            "findings": evaluation.get("evaluations", []),
        },
    }
    return json.dumps(report, indent=2)
