"""CLI interface — the main entry point for Sentinel."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from sentinel import __version__
from sentinel.diff import full_diff
from sentinel.manifest import save_snapshot, load_snapshot, list_snapshots, get_snapshot_label
from sentinel.policy import evaluate_diff, add_to_allowlist, remove_from_allowlist
from sentinel.report import print_terminal_report, json_report
from sentinel.snapshot import take_snapshot
from sentinel.signing import sign_manifest, verify_manifest, _get_default_key, _gpg_available
from sentinel.incident import list_incidents, get_incident, get_incident_stats, export_incidents, log_incident
from sentinel.daemon import (
    run_daemon, is_running, write_pid, remove_pid,
    load_config, save_config, setup_signal_handlers,
)
from sentinel.dashboard import start_dashboard


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Take a system state snapshot and save it."""
    label = args.label or ""
    extra_paths = [Path(p) for p in args.paths] if args.paths else None

    print(f"📸 Taking snapshot{' — ' + label if label else ''}...", file=sys.stderr)

    snapshot = take_snapshot(
        label=label,
        extra_paths=extra_paths,
        include_user_config=not args.no_user_config,
    )

    path = save_snapshot(snapshot, label=label)
    print(f"✓ Saved snapshot to {path}", file=sys.stderr)
    print(path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command between pre and post snapshots."""
    model_dirs = args.model_dir or []
    label = args.label or "run"
    cmd = args.cmd
    extra_paths = [Path(p) for p in args.paths] if args.paths else None

    if not cmd:
        print("Error: no command specified.", file=sys.stderr)
        return 1

    # Pre snapshot
    print(f"🔍 Taking pre-execution snapshot...", file=sys.stderr)
    pre = take_snapshot(
        label=f"{label}_pre",
        extra_paths=extra_paths,
        include_user_config=not args.no_user_config,
    )
    pre_path = save_snapshot(pre, label=f"{label}_pre")
    print(f"  ✓ Baseline: {pre_path}", file=sys.stderr)

    # Run the command
    print(f"▶ Running: {cmd}", file=sys.stderr)
    try:
        result = subprocess.run(
            shlex.split(cmd),
            timeout=args.timeout,
        )
        print(f"  ✓ Command exited with code {result.returncode}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"  ⚠ Command timed out after {args.timeout}s", file=sys.stderr)
    except FileNotFoundError:
        print(f"  ✗ Command not found: {cmd}", file=sys.stderr)
        return 1

    # Post snapshot
    print(f"📸 Taking post-execution snapshot...", file=sys.stderr)
    post = take_snapshot(
        label=f"{label}_post",
        extra_paths=extra_paths,
        include_user_config=not args.no_user_config,
    )
    post_path = save_snapshot(post, label=f"{label}_post")
    print(f"  ✓ Post-check: {post_path}", file=sys.stderr)

    # Diff and evaluate
    diff_result = full_diff(pre, post)
    policy_result = evaluate_diff(diff_result, model_dirs)

    # Report
    if args.format == "json":
        print(json_report(diff_result, policy_result))
    else:
        report = print_terminal_report(diff_result, policy_result, model_dirs)
        print(report)

    # Log to incident audit trail
    counts = policy_result.get("counts", {})
    verdict = policy_result.get("verdict", "UNKNOWN")
    evaluations = policy_result.get("evaluations", [])
    has_issues = counts.get("critical", 0) > 0 or counts.get("suspicious", 0) > 0 or counts.get("info", 0) > 0

    # Build a summary
    summary_parts = []
    if counts.get("critical", 0):
        summary_parts.append(f"{counts['critical']} critical")
    if counts.get("suspicious", 0):
        summary_parts.append(f"{counts['suspicious']} suspicious")
    if counts.get("info", 0):
        summary_parts.append(f"{counts['info']} info")
    summary = ", ".join(summary_parts) or "clean"

    log_incident(
        verdict=verdict,
        severity_counts=counts,
        pre_snapshot=pre_path,
        post_snapshot=post_path,
        command=cmd,
        label=label,
        model_dirs=model_dirs,
        summary=summary,
        findings_count=len(evaluations),
    )

    # Exit code based on verdict
    if counts.get("critical", 0) > 0:
        return 2
    if counts.get("suspicious", 0) > 0:
        return 1
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two existing snapshots."""
    pre_path = Path(args.pre)
    post_path = Path(args.post)

    if not pre_path.exists():
        print(f"Error: baseline snapshot not found: {pre_path}", file=sys.stderr)
        return 1
    if not post_path.exists():
        print(f"Error: post snapshot not found: {post_path}", file=sys.stderr)
        return 1

    pre = load_snapshot(pre_path)
    post = load_snapshot(post_path)
    model_dirs = args.model_dir or []

    diff_result = full_diff(pre, post)
    policy_result = evaluate_diff(diff_result, model_dirs)

    if args.format == "json":
        print(json_report(diff_result, policy_result))
    else:
        report = print_terminal_report(diff_result, policy_result, model_dirs)
        print(report)

    counts = policy_result.get("counts", {})
    if counts.get("critical", 0) > 0:
        return 2
    if counts.get("suspicious", 0) > 0:
        return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List saved snapshots."""
    snaps = list_snapshots()
    if not snaps:
        print("No snapshots found.", file=sys.stderr)
        return 0

    print(f"{'#':>3}  {'Timestamp':<20}  {'Label':<20}  {'Path'}")
    print("-" * 80)
    for i, snap in enumerate(snaps, 1):
        label = get_snapshot_label(snap)
        ts = snap.stem.replace("sentinel_", "").split("_")[0] if snap.stem.startswith("sentinel_") else "?"
        # Reformat timestamp for display
        if len(ts) == 15:  # YYYYMMDD_HHMMSS
            ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"
        print(f"{i:>3}  {ts:<20}  {label:<20}  {snap}")
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    """Manage the allowlist."""
    if args.add:
        add_to_allowlist(args.add)
        print(f"✓ Added to allowlist: {args.add}", file=sys.stderr)
    elif args.remove:
        remove_from_allowlist(args.remove)
        print(f"✓ Removed from allowlist: {args.remove}", file=sys.stderr)
    else:
        from sentinel.policy import _load_allowlist
        paths = _load_allowlist()
        if paths:
            print("Allowlisted paths:")
            for p in sorted(paths):
                print(f"  {p}")
        else:
            print("Allowlist is empty.", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show current system state (quick summary, no comparison)."""
    snapshot = take_snapshot(label="status")
    files = snapshot.get("files", {})
    total = sum(len(v) for v in files.values() if isinstance(v, dict))
    procs = len(snapshot.get("processes", {}))
    svcs = len(snapshot.get("services", {}))

    print(f"  Host:      {snapshot['meta']['hostname']}")
    print(f"  Time:      {snapshot['meta']['timestamp']}")
    print(f"  Files:     {total} files tracked")
    print(f"  Processes: {procs} running")
    print(f"  Services:  {svcs} tracked")
    print(f"  Manifest:  {snapshot['meta']['manifest_hash'][:16]}...")
    print(f"\n  Use `sentinel run <command>` to wrap a model execution.")
    return 0


# ── New Commands ────────────────────────────────────────────────────────


def cmd_sign(args: argparse.Namespace) -> int:
    """GPG-sign a manifest file."""
    manifest_path = Path(args.manifest)

    if not manifest_path.exists():
        print(f"Error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    if not _gpg_available():
        print("Error: GPG is not available on this system.", file=sys.stderr)
        print("Install gnupg and create a signing key first.", file=sys.stderr)
        return 1

    key_id = args.key or _get_default_key()
    if not key_id:
        print("Error: No GPG signing key found.", file=sys.stderr)
        print("  Create one: gpg --full-generate-key", file=sys.stderr)
        print("  Or specify: sentinel sign --key KEYID manifest.json", file=sys.stderr)
        return 1

    print(f"🔑 Signing with key: {key_id}", file=sys.stderr)
    sig_path = sign_manifest(manifest_path, key_id)

    if sig_path:
        print(f"✓ Signature saved to: {sig_path}", file=sys.stderr)
        return 0
    else:
        print("✗ Signing failed.", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a GPG-signed manifest."""
    manifest_path = Path(args.manifest)

    if not manifest_path.exists():
        print(f"Error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1

    print(f"🔍 Verifying: {manifest_path}", file=sys.stderr)
    valid, details = verify_manifest(manifest_path)

    if valid:
        print(f"✓ ✅ Signature valid!", file=sys.stderr)
        print(f"  {details}", file=sys.stderr)
        return 0
    else:
        print(f"✗ Signature verification failed: {details}", file=sys.stderr)
        return 1


def cmd_daemon(args: argparse.Namespace) -> int:
    """Manage the Sentinel daemon."""
    action = args.action

    if action == "status":
        running = is_running()
        config = load_config()
        print(f"  Daemon: {'🟢 Running' if running else '🔴 Stopped'}")
        print(f"  Interval: {config.get('interval_seconds', 3600)}s")
        print(f"  Baseline: {config.get('baseline_snapshot', 'not set')}")
        if config.get("notify_command"):
            print(f"  Notify:   {config['notify_command']}")
        return 0

    elif action == "start":
        if is_running():
            print("Daemon is already running.", file=sys.stderr)
            return 1
        interval = args.interval
        print(f"🟢 Starting Sentinel daemon (interval: {interval}s)...", file=sys.stderr)
        # Signal handling for graceful shutdown
        setup_signal_handlers()
        write_pid()
        run_daemon(interval=interval)
        return 0

    elif action == "stop":
        import signal as _sig
        pid_path = Path.home() / ".sentinel" / "daemon.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
                os.kill(pid, _sig.SIGTERM)
                pid_path.unlink(missing_ok=True)
                print("✓ Daemon stopped.", file=sys.stderr)
            except (ProcessLookupError, OSError):
                pid_path.unlink(missing_ok=True)
                print("Daemon was not running.", file=sys.stderr)
        else:
            print("Daemon is not running.", file=sys.stderr)
        return 0

    elif action == "init":
        print("Initializing daemon baseline...", file=sys.stderr)
        from sentinel.snapshot import take_snapshot
        from sentinel.manifest import save_snapshot
        snapshot = take_snapshot(label="daemon_baseline")
        path = save_snapshot(snapshot, label="daemon_baseline")
        config = load_config()
        config["baseline_snapshot"] = str(path)
        if args.interval:
            config["interval_seconds"] = args.interval
        if args.notify:
            config["notify_command"] = args.notify
        save_config(config)
        print(f"✓ Baseline saved: {path}", file=sys.stderr)
        print(f"✓ Config updated", file=sys.stderr)
        return 0

    elif action == "config":
        config = load_config()
        import json
        print(json.dumps(config, indent=2))
        return 0

    else:
        print(f"Unknown daemon action: {action}", file=sys.stderr)
        return 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Start the Sentinel web dashboard."""
    port = args.port
    no_browser = args.no_browser
    start_dashboard(port=port, open_browser=not no_browser)
    return 0


def cmd_incidents(args: argparse.Namespace) -> int:
    """List or view incidents from the audit trail."""
    action = args.action

    if action == "list":
        limit = args.limit
        incidents = list_incidents(limit=limit)
        if not incidents:
            print("No incidents recorded yet.", file=sys.stderr)
            return 0

        print(f"{'ID':<12} {'Timestamp':<30} {'Verdict':<40} {'Findings'}")
        print("-" * 110)
        for inc in incidents:
            sev = ""
            sc = inc.get("severity_counts", {})
            parts = []
            if sc.get("critical"):
                parts.append(f"🔴{sc['critical']}")
            if sc.get("suspicious"):
                parts.append(f"🟡{sc['suspicious']}")
            if sc.get("info"):
                parts.append(f"🔵{sc['info']}")
            sev = " ".join(parts)
            print(f"{inc.get('id', '?'):<12} {inc.get('timestamp', '?'):<30} "
                  f"{inc.get('verdict', '?'):<40} {sev}")
        return 0

    elif action == "stats":
        stats = get_incident_stats()
        print(f"  Total incidents: {stats.get('total', 0)}")
        for verdict, count in stats.get("verdict_summary", {}).items():
            print(f"    {verdict}: {count}")
        return 0

    elif action == "export":
        fmt = args.format
        print(export_incidents(format=fmt))
        return 0

    else:
        # Default: show latest incidents
        incidents = list_incidents(limit=10)
        if not incidents:
            print("No incidents recorded yet.", file=sys.stderr)
            return 0
        for inc in incidents:
            print(f"[{inc.get('id', '?')}] {inc.get('timestamp', '?')} — {inc.get('verdict', '?')}")
            if inc.get("summary"):
                print(f"      {inc['summary']}")
        return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="AI Model Runtime Integrity Checker",
        epilog="Example: sentinel run --model-dir ./models './run-model.sh'",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── snapshot ──────────────────────────────────────────────────────
    p_snap = sub.add_parser("snapshot", help="Take a system state snapshot")
    p_snap.add_argument("--label", "-l", default="", help="Human-readable label")
    p_snap.add_argument("--path", "-p", dest="paths", action="append", default=[],
                        help="Extra paths to monitor (can repeat)")
    p_snap.add_argument("--no-user-config", action="store_true",
                        help="Skip user config file monitoring")
    p_snap.set_defaults(func=cmd_snapshot)

    # ── run ───────────────────────────────────────────────────────────
    p_run = sub.add_parser("run", help="Run a command wrapped with pre/post snapshots")
    p_run.add_argument("cmd", nargs="?", metavar="COMMAND", help="Command to execute (e.g. './run-llama.sh')")
    p_run.add_argument("--label", "-l", default="run", help="Label for this run")
    p_run.add_argument("--model-dir", "-m", dest="model_dir", action="append", default=[],
                       help="Model working directory (can repeat)")
    p_run.add_argument("--path", "-p", dest="paths", action="append", default=[],
                       help="Extra paths to monitor (can repeat)")
    p_run.add_argument("--format", "-f", choices=["terminal", "json"], default="terminal",
                       help="Output format")
    p_run.add_argument("--timeout", "-t", type=int, default=3600,
                       help="Command timeout in seconds (default: 3600)")
    p_run.add_argument("--no-user-config", action="store_true",
                       help="Skip user config file monitoring")
    p_run.set_defaults(func=cmd_run)

    # ── diff ──────────────────────────────────────────────────────────
    p_diff = sub.add_parser("diff", help="Compare two existing snapshots")
    p_diff.add_argument("pre", help="Baseline snapshot file")
    p_diff.add_argument("post", help="Post-execution snapshot file")
    p_diff.add_argument("--model-dir", "-m", dest="model_dir", action="append", default=[],
                        help="Model working directory (can repeat)")
    p_diff.add_argument("--format", "-f", choices=["terminal", "json"], default="terminal",
                        help="Output format")
    p_diff.set_defaults(func=cmd_diff)

    # ── list ──────────────────────────────────────────────────────────
    p_list = sub.add_parser("list", help="List saved snapshots")
    p_list.set_defaults(func=cmd_list)

    # ── allow ─────────────────────────────────────────────────────────
    p_allow = sub.add_parser("allow", help="Manage the allowlist")
    p_allow.add_argument("--add", "-a", help="Add a path to the allowlist")
    p_allow.add_argument("--remove", "-r", help="Remove a path from the allowlist")
    p_allow.set_defaults(func=cmd_allow)

    # ── status ────────────────────────────────────────────────────────
    p_status = sub.add_parser("status", help="Show current system state overview")
    p_status.set_defaults(func=cmd_status)

    # ── sign ──────────────────────────────────────────────────────────
    p_sign = sub.add_parser("sign", help="Sign a manifest with GPG")
    p_sign.add_argument("manifest", help="Path to the manifest JSON file")
    p_sign.add_argument("--key", "-k", default="", help="GPG key ID to sign with")
    p_sign.set_defaults(func=cmd_sign)

    # ── verify ────────────────────────────────────────────────────────
    p_verify = sub.add_parser("verify", help="Verify a GPG-signed manifest")
    p_verify.add_argument("manifest", help="Path to the manifest JSON file")
    p_verify.set_defaults(func=cmd_verify)

    # ── daemon ────────────────────────────────────────────────────────
    p_daemon = sub.add_parser("daemon", help="Manage the background monitoring daemon")
    p_daemon.add_argument("action", choices=["start", "stop", "status", "init", "config"],
                          help="Daemon action")
    p_daemon.add_argument("--interval", "-i", type=int, default=3600,
                          help="Check interval in seconds (for start/init)")
    p_daemon.add_argument("--notify", "-n", default="",
                          help="External command to run on alert (for init)")
    p_daemon.set_defaults(func=cmd_daemon)

    # ── dashboard ─────────────────────────────────────────────────────
    p_dash = sub.add_parser("dashboard", help="Start the web-based dashboard GUI")
    p_dash.add_argument("--port", "-p", type=int, default=8099,
                        help="HTTP port (default: 8099)")
    p_dash.add_argument("--no-browser", action="store_true",
                        help="Don't open a browser automatically")
    p_dash.set_defaults(func=cmd_dashboard)

    # ── incidents ─────────────────────────────────────────────────────
    p_inc = sub.add_parser("incidents", help="View the incident audit trail")
    p_inc.add_argument("action", nargs="?", choices=["list", "stats", "export"],
                       default="list", help="Incident action")
    p_inc.add_argument("--limit", "-l", type=int, default=50,
                       help="Max incidents to show (for list)")
    p_inc.add_argument("--format", "-f", choices=["json", "lines", "text"], default="text",
                       help="Export format (for export)")
    p_inc.set_defaults(func=cmd_incidents)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except PermissionError:
        print(
            "Error: Permission denied. Try running with sudo for full system access.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
