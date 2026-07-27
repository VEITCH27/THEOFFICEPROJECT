"""Signed manifests — GPG sign and verify snapshot integrity."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple


SIGNATURE_EXT = ".sig"
DEFAULT_KEY_ID = ""


def _gpg_available() -> bool:
    """Check if gpg is available on the system."""
    try:
        subprocess.run(
            ["gpg", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def _get_default_key() -> Optional[str]:
    """Get the default GPG signing key."""
    try:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--keyid-format=long"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "sec" in line and "/" in line:
                # Extract key ID from line like "sec   rsa4096/ABCDEF1234567890 2024-01-01"
                parts = line.split()
                for part in parts:
                    if "/" in part:
                        return part.split("/")[1]
        return None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def sign_manifest(manifest_path: Path, key_id: Optional[str] = None) -> Optional[Path]:
    """GPG-sign a manifest file.

    Creates a detached `.sig` file alongside the manifest.

    Args:
        manifest_path: Path to the JSON manifest.
        key_id: GPG key ID. If None, uses the default key.

    Returns:
        Path to the signature file, or None if signing failed.
    """
    if not _gpg_available():
        print("  ⚠ GPG not available — skipping signature", file=__import__('sys').stderr)
        return None

    key_id = key_id or _get_default_key()
    if not key_id:
        print("  ⚠ No GPG signing key found — skipping signature", file=__import__('sys').stderr)
        return None

    sig_path = manifest_path.with_suffix(manifest_path.suffix + SIGNATURE_EXT)

    try:
        result = subprocess.run(
            ["gpg", "--detach-sign", "--armor",
             "--default-key", key_id,
             "--output", str(sig_path),
             str(manifest_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"  ⚠ GPG signing failed: {result.stderr.strip()}", file=__import__('sys').stderr)
            return None
        return sig_path
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"  ⚠ GPG signing error: {e}", file=__import__('sys').stderr)
        return None


def verify_manifest(manifest_path: Path) -> Tuple[bool, str]:
    """Verify the GPG signature of a manifest file.

    Returns:
        (is_valid, details_string)
    """
    sig_path = manifest_path.with_suffix(manifest_path.suffix + SIGNATURE_EXT)

    if not sig_path.exists():
        return False, "No signature file found"

    if not _gpg_available():
        return False, "GPG not available"

    try:
        result = subprocess.run(
            ["gpg", "--verify", str(sig_path), str(manifest_path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            # Extract signer info from stderr (gpg writes status there)
            signer = ""
            for line in result.stderr.splitlines():
                if "using" in line and "key" in line:
                    signer = line.strip()
                if "Good signature" in line:
                    signer = line.strip() + " | " + signer
            return True, signer or "Good signature"
        else:
            return False, result.stderr.strip()[:200]
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        return False, str(e)


def sign_snapshot_data(
    snapshot: Dict,
    manifest_path: Path,
    key_id: Optional[str] = None,
) -> Optional[Path]:
    """Save a snapshot to a manifest file and sign it in one operation.

    Returns:
        Path to the signature file, or None.
    """
    # Save manifest
    from sentinel.manifest import save_snapshot
    path = save_snapshot(snapshot, path=manifest_path)

    # Sign it
    sig_path = sign_manifest(path, key_id)

    # Embed signature info in snapshot metadata if signing succeeded
    if sig_path:
        try:
            sig_content = sig_path.read_text()
            snapshot.setdefault("meta", {})["signature"] = {
                "type": "gpg-detached-armor",
                "file": str(sig_path.name),
                "key_id": key_id or "",
            }
            # Re-save with embedded signature metadata
            path.write_text(json.dumps(snapshot, indent=2, default=str))
        except OSError:
            pass

    return sig_path
