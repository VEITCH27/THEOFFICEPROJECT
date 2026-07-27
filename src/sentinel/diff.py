"""Diff engine — compare two system snapshots and classify changes."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from sentinel.defaults import CRITICAL_PATHS, SUSPICIOUS_PATHS, VOLATILE_PROCESS_PATTERNS


def classify_path(path: str) -> str:
    """Classify a file path by its monitored category."""
    p = Path(path).resolve()
    for critical in CRITICAL_PATHS:
        if critical.resolve() in p.parents or critical.resolve() == p:
            return "critical"
    for suspicious in SUSPICIOUS_PATHS:
        if suspicious.resolve() in p.parents or suspicious.resolve() == p:
            return "suspicious"
    return "monitored"


def _is_volatile_process(proc: Dict) -> bool:
    """Check if a process name matches known-volatile patterns."""
    name = proc.get("name", "")
    for pattern in VOLATILE_PROCESS_PATTERNS:
        if pattern in name:
            return True
    return False


def diff_files(pre: Dict, post: Dict) -> Dict[str, List[Dict]]:
    """Compare file hashes between pre and post snapshots.

    Returns:
        {"added": [...], "removed": [...], "modified": [...], "unchanged": int}
    """
    pre_files = pre.get("files", {})
    post_files = post.get("files", {})

    # Flatten all file categories into one dict per snapshot
    def _flatten(files_dict: Dict) -> Dict[str, Dict]:
        result = {}
        for category, entries in files_dict.items():
            if isinstance(entries, dict):
                for path, entry in entries.items():
                    result[path] = {**entry, "_category": category}
        return result

    pre_flat = _flatten(pre_files)
    post_flat = _flatten(post_files)

    pre_paths = set(pre_flat.keys())
    post_paths = set(post_flat.keys())

    added_paths = post_paths - pre_paths
    removed_paths = pre_paths - post_paths
    common_paths = pre_paths & post_paths

    added = []
    for path in sorted(added_paths):
        entry = post_flat[path]
        added.append({
            "path": path,
            "category": entry.get("_category", "extra"),
            "volatile": entry.get("volatile", False),
            "sha256": entry.get("sha256", ""),
            "size": entry.get("size", 0),
            "mode": entry.get("mode", ""),
        })

    removed = []
    for path in sorted(removed_paths):
        entry = pre_flat[path]
        removed.append({
            "path": path,
            "category": entry.get("_category", "extra"),
            "volatile": entry.get("volatile", False),
            "sha256": entry.get("sha256", ""),
        })

    modified = []
    unchanged = 0
    for path in sorted(common_paths):
        pre_entry = pre_flat[path]
        post_entry = post_flat[path]

        if pre_entry.get("sha256") != post_entry.get("sha256"):
            modified.append({
                "path": path,
                "category": post_entry.get("_category", "extra"),
                "volatile": post_entry.get("volatile", False),
                "pre_sha256": pre_entry.get("sha256", ""),
                "post_sha256": post_entry.get("sha256", ""),
                "pre_size": pre_entry.get("size", 0),
                "post_size": post_entry.get("size", 0),
                "pre_mode": pre_entry.get("mode", ""),
                "post_mode": post_entry.get("mode", ""),
            })
        else:
            unchanged += 1

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged_count": unchanged,
    }


def diff_processes(pre: Dict, post: Dict) -> Dict[str, List]:
    """Compare running processes between pre and post snapshots.

    Filters out known-volatile kernel threads.
    """
    pre_procs = {k: v for k, v in pre.get("processes", {}).items() if not _is_volatile_process(v)}
    post_procs = {k: v for k, v in post.get("processes", {}).items() if not _is_volatile_process(v)}

    pre_names = set(pre_procs.keys())
    post_names = set(post_procs.keys())

    new_pids = post_names - pre_names
    gone_pids = pre_names - post_names

    new_procs = [{"pid": post_procs[p]["pid"], "name": post_procs[p]["name"], "cmdline": post_procs[p].get("cmdline", "")[:100]}
                 for p in sorted(new_pids)]
    gone_procs = [{"pid": pre_procs[p]["pid"], "name": pre_procs[p]["name"]}
                  for p in sorted(gone_pids)]

    return {
        "new": new_procs,
        "gone": gone_procs,
        "new_count": len(new_procs),
        "gone_count": len(gone_procs),
    }


def diff_services(pre: Dict, post: Dict) -> Dict[str, List]:
    """Compare systemd service states."""
    pre_svcs = pre.get("services", {})
    post_svcs = post.get("services", {})

    changed = []
    all_units = set(pre_svcs.keys()) | set(post_svcs.keys())
    for unit in sorted(all_units):
        if pre_svcs.get(unit) != post_svcs.get(unit):
            changed.append({
                "unit": unit,
                "pre": pre_svcs.get(unit, {}).get("active", "N/A"),
                "post": post_svcs.get(unit, {}).get("active", "N/A"),
            })

    return {"changed": changed, "changed_count": len(changed)}


def diff_cron(pre: Dict, post: Dict) -> Dict[str, List]:
    """Compare cron configurations."""
    pre_cron = pre.get("cron", {})
    post_cron = post.get("cron", {})

    diffs = []

    # System cron files
    pre_system = {c["file"]: c.get("content", "") for c in pre_cron.get("system", [])}
    post_system = {c["file"]: c.get("content", "") for c in post_cron.get("system", [])}

    all_files = set(pre_system.keys()) | set(post_system.keys())
    for f in sorted(all_files):
        pre_c = pre_system.get(f, "")
        post_c = post_system.get(f, "")
        if pre_c != post_c:
            diffs.append({"type": "system_cron", "file": f, "changed": True})

    # User crontabs
    pre_users = pre_cron.get("users", {})
    post_users = post_cron.get("users", {})
    all_users = set(pre_users.keys()) | set(post_users.keys())
    for user in sorted(all_users):
        if pre_users.get(user) != post_users.get(user):
            diffs.append({
                "type": "user_crontab",
                "user": user,
                "changed": True,
                "pre_length": len(pre_users.get(user, "")),
                "post_length": len(post_users.get(user, "")),
            })

    return {"changes": diffs, "change_count": len(diffs)}


def diff_network(pre: Dict, post: Dict) -> Dict[str, bool]:
    """Quick check if network config changed (true/false per section)."""
    pre_net = pre.get("network", {})
    post_net = post.get("network", {})
    return {
        "interfaces_changed": pre_net.get("interfaces") != post_net.get("interfaces"),
        "routing_changed": pre_net.get("routing") != post_net.get("routing"),
        "dns_changed": pre_net.get("dns") != post_net.get("dns"),
        "listening_changed": pre_net.get("listening") != post_net.get("listening"),
        "firewall_changed": pre_net.get("iptables") != post_net.get("iptables")
        or pre_net.get("nftables") != post_net.get("nftables"),
    }


def diff_kernel(pre: Dict, post: Dict) -> Dict[str, bool]:
    """Quick check if kernel state changed."""
    pre_k = pre.get("kernel", {})
    post_k = post.get("kernel", {})
    return {
        "modules_changed": pre_k.get("modules") != post_k.get("modules"),
        "sysctl_changed": pre_k.get("sysctl") != post_k.get("sysctl"),
    }


def full_diff(pre: Dict, post: Dict) -> Dict:
    """Produce a full structured diff between two snapshots."""
    return {
        "pre_label": pre.get("meta", {}).get("label", "pre"),
        "post_label": post.get("meta", {}).get("label", "post"),
        "pre_timestamp": pre.get("meta", {}).get("timestamp", ""),
        "post_timestamp": post.get("meta", {}).get("timestamp", ""),
        "manifest_hash_match": pre.get("meta", {}).get("manifest_hash")
        == post.get("meta", {}).get("manifest_hash"),
        "files": diff_files(pre, post),
        "processes": diff_processes(pre, post),
        "services": diff_services(pre, post),
        "cron": diff_cron(pre, post),
        "network": diff_network(pre, post),
        "kernel": diff_kernel(pre, post),
    }
