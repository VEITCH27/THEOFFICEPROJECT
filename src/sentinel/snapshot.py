"""Snapshot engine — captures system state as a cryptographic manifest."""

from __future__ import annotations

import hashlib
import os
import pwd
import shutil
import subprocess
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from sentinel.defaults import (
    CRITICAL_PATHS,
    SUSPICIOUS_PATHS,
    USER_CONFIG_PATHS,
    EXCLUDE_GLOBS,
    VOLATILE_PATTERNS,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _should_exclude(path: Path) -> bool:
    """Check if a path should be excluded from scanning."""
    name = path.name
    for pattern in EXCLUDE_GLOBS:
        if pattern.startswith("*") and name.endswith(pattern[1:]):
            return True
        if pattern == name:
            return True
    for part in path.parts:
        if part in EXCLUDE_GLOBS:
            return True
    return False


def _is_volatile(path: Path) -> bool:
    """Check if a path is in a known-volatile location."""
    str_path = str(path.resolve())
    for pattern in VOLATILE_PATTERNS:
        if pattern in str_path:
            return True
    return False


def _hash_file(path: Path) -> Optional[str]:
    """Return SHA-256 hex digest of a file, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            # 64KB chunks to handle large files
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return os.stat(path)
    except OSError:
        return None


def _walk_paths(paths: List[Path]) -> Dict[Path, Dict]:
    """Walk a list of paths and return {path: {hash, mode, size, uid, gid}}."""
    results: Dict[Path, Dict] = {}
    seen: Set[Path] = set()

    for root in paths:
        root = root.expanduser().resolve()
        if not root.exists():
            continue

        if root.is_file():
            if root in seen or _should_exclude(root):
                continue
            seen.add(root)
            entry = _file_entry(root)
            if entry:
                results[root] = entry
        else:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dir_path = Path(dirpath)

                # Filter excluded dirs in-place so os.walk skips them
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not _should_exclude(dir_path / d)
                ]

                for filename in filenames:
                    fpath = dir_path / filename
                    if fpath in seen or _should_exclude(fpath):
                        continue
                    seen.add(fpath)
                    entry = _file_entry(fpath)
                    if entry:
                        results[fpath] = entry

    return results


def _file_entry(path: Path) -> Optional[Dict]:
    """Create a file entry dict with hash, metadata, and volatility flag."""
    st = _safe_stat(path)
    if st is None:
        return None

    fhash = _hash_file(path)
    if fhash is None:
        return None

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)

    return {
        "sha256": fhash,
        "size": st.st_size,
        "mode": stat.filemode(st.st_mode),
        "owner": owner,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime": st.st_mtime,
        "volatile": _is_volatile(path),
    }


# ── System State Collectors ──────────────────────────────────────────────


def _collect_processes() -> Dict[str, Dict]:
    """Snapshot running processes."""
    processes = {}
    try:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            try:
                cmdline = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                status = {}
                for line in (proc_dir / "status").read_text(errors="replace").splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        status[k.strip()] = v.strip()
                comm = status.get("Name", cmdline.split()[0] if cmdline else "?")
                processes[proc_dir.name] = {
                    "pid": int(proc_dir.name),
                    "name": comm,
                    "cmdline": cmdline[:200] if cmdline else "",
                    "uid": status.get("Uid", "").split("\t")[0],
                    "state": status.get("State", ""),
                    "ppid": status.get("PPid", ""),
                }
            except (PermissionError, FileNotFoundError, OSError):
                continue
    except PermissionError:
        pass
    return processes


def _collect_services() -> Dict[str, Dict]:
    """Snapshot systemd service states (if systemd is available)."""
    services = {}
    if not shutil.which("systemctl"):
        return services
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                services[parts[0]] = {
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": " ".join(parts[4:]) if len(parts) > 4 else "",
                }
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return services


def _collect_cron() -> Dict[str, List[str]]:
    """Snapshot cron jobs for all users with crontabs."""
    cron = {"system": [], "users": {}}
    # System cron dirs
    for cron_dir in [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]:
        if cron_dir.is_file():
            try:
                cron["system"].append({"file": str(cron_dir), "content": cron_dir.read_text(errors="replace")[:1000]})
            except PermissionError:
                pass
        elif cron_dir.is_dir():
            for f in sorted(cron_dir.iterdir()):
                if f.is_file():
                    try:
                        cron["system"].append({"file": str(f), "content": f.read_text(errors="replace")[:1000]})
                    except PermissionError:
                        pass

    # User crontabs
    if shutil.which("crontab"):
        try:
            for pw_entry in pwd.getpwall():
                if pw_entry.pw_uid < 1000:
                    continue
                try:
                    result = subprocess.run(
                        ["crontab", "-u", pw_entry.pw_name, "-l"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.stdout.strip():
                        cron["users"][pw_entry.pw_name] = result.stdout.strip()[:2000]
                except (subprocess.SubprocessError, PermissionError):
                    continue
        except Exception:
            pass

    return cron


def _collect_network() -> Dict[str, any]:
    """Snapshot network configuration."""
    net = {}
    # Interfaces
    try:
        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5)
        net["interfaces"] = result.stdout.strip()[:3000]
    except (subprocess.SubprocessError, FileNotFoundError):
        try:
            result = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, timeout=5)
            net["interfaces"] = result.stdout.strip()[:3000]
        except (subprocess.SubprocessError, FileNotFoundError):
            net["interfaces"] = ""

    # Routing table
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        net["routing"] = result.stdout.strip()[:2000]
    except (subprocess.SubprocessError, FileNotFoundError):
        net["routing"] = ""

    # DNS
    try:
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            net["dns"] = resolv.read_text(errors="replace")[:2000]
    except PermissionError:
        net["dns"] = ""

    # Listening ports
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=5,
        )
        net["listening"] = result.stdout.strip()[:3000]
    except (subprocess.SubprocessError, FileNotFoundError):
        net["listening"] = ""

    # Firewall rules
    for cmd, key in [
        (["iptables", "-L", "-n"], "iptables"),
        (["nft", "list", "ruleset"], "nftables"),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            net[key] = result.stdout.strip()[:3000]
        except (subprocess.SubprocessError, FileNotFoundError):
            net[key] = ""
        except PermissionError:
            net[key] = "(permission denied)"

    return net


def _collect_kernel() -> Dict[str, str]:
    """Snapshot kernel state information."""
    kernel = {}
    try:
        kernel["modules"] = Path("/proc/modules").read_text(errors="replace")[:3000]
    except (PermissionError, FileNotFoundError):
        kernel["modules"] = ""
    try:
        kernel["sysctl"] = subprocess.run(
            ["sysctl", "-a"], capture_output=True, text=True, timeout=10
        ).stdout.strip()[:3000]
    except (subprocess.SubprocessError, FileNotFoundError):
        kernel["sysctl"] = ""
    try:
        kernel["uname"] = subprocess.run(
            ["uname", "-a"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        kernel["uname"] = ""
    return kernel


# ── Main Snapshot Function ───────────────────────────────────────────────


def take_snapshot(
    label: str = "",
    extra_paths: Optional[List[Path]] = None,
    include_user_config: bool = True,
) -> Dict:
    """Take a full system state snapshot.

    Returns a dictionary that can be serialized and diffed.
    """
    critical = _walk_paths(CRITICAL_PATHS)
    suspicious = _walk_paths(SUSPICIOUS_PATHS)
    user_config = _walk_paths([Path(p) for p in USER_CONFIG_PATHS]) if include_user_config else {}
    extra = _walk_paths(extra_paths) if extra_paths else {}

    snapshot = {
        # Metadata
        "meta": {
            "label": label,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename,
            "version": "0.1.0",
        },
        # File integrity
        "files": {
            "critical": {str(k): v for k, v in critical.items()},
            "suspicious": {str(k): v for k, v in suspicious.items()},
            "user_config": {str(k): v for k, v in user_config.items()},
            "extra": {str(k): v for k, v in extra.items()},
        },
        # Runtime state
        "processes": _collect_processes(),
        "services": _collect_services(),
        "cron": _collect_cron(),
        "network": _collect_network(),
        "kernel": _collect_kernel(),
    }

    # Top-level rolling hash of the entire snapshot content
    snapshot["meta"]["manifest_hash"] = _compute_manifest_hash(snapshot)

    return snapshot


def _compute_manifest_hash(snapshot: Dict) -> str:
    """Compute a rolling SHA-256 hash of the snapshot's file entries."""
    h = hashlib.sha256()
    for category in ("critical", "suspicious", "user_config", "extra"):
        files = snapshot.get("files", {}).get(category, {})
        for path in sorted(files.keys()):
            h.update(path.encode())
            entry = files[path]
            h.update(entry.get("sha256", "").encode())
            h.update(str(entry.get("mode", "")).encode())
            h.update(str(entry.get("uid", "")).encode())
    return h.hexdigest()
