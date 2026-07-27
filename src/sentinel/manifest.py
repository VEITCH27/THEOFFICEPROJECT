"""Manifest serialization — save, load, and verify snapshot integrity."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from sentinel.defaults import MANIFEST_DIR


def save_snapshot(snapshot: Dict, path: Optional[Path] = None, label: str = "") -> Path:
    """Serialize a snapshot to JSON and save it.

    Args:
        snapshot: The snapshot dict from snapshot.take_snapshot().
        path: Explicit path. If None, auto-generate under MANIFEST_DIR.
        label: Human-readable label for the snapshot.

    Returns:
        Path to the saved manifest file.
    """
    if path is None:
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        label_part = f"_{label}" if label else ""
        filename = f"sentinel_{timestamp}{label_part}.json"
        path = MANIFEST_DIR / filename

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, default=str))
    return path


def load_snapshot(path: Path) -> Dict:
    """Load a snapshot from a JSON manifest file."""
    return json.loads(path.read_text())


def list_snapshots(manifest_dir: Optional[Path] = None) -> list[Path]:
    """List all snapshot manifest files in order (newest first)."""
    directory = manifest_dir or MANIFEST_DIR
    if not directory.exists():
        return []
    files = sorted(directory.glob("sentinel_*.json"), reverse=True)
    return files


def get_snapshot_label(path: Path) -> str:
    """Extract the human-readable label from a snapshot path/filename."""
    try:
        data = json.loads(path.read_text())
        return data.get("meta", {}).get("label", "")
    except (json.JSONDecodeError, OSError):
        return ""
