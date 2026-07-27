#!/usr/bin/env python3
"""Build standalone Sentinel binaries using PyInstaller.

Usage:
    python build/build.py           # Build for current platform
    python build/build.py --all     # Cross-platform hint for CI

Requires:
    pip install pyinstaller
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build" / "pyinstaller"
SPEC_FILE = ROOT / "build" / "sentinel.spec"


def build_binary() -> Path:
    """Build a standalone Sentinel binary with PyInstaller."""
    print(f"🔧 Building Sentinel binary for {platform.system()} {platform.machine()}...")

    # Ensure PyInstaller is available
    try:
        import PyInstaller  # noqa
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyinstaller"]
        )

    # Clean previous builds
    for p in [DIST / "sentinel", BUILD]:
        if p.exists():
            shutil.rmtree(p)

    # Use spec file if it exists, otherwise run pyinstaller directly
    spec = SPEC_FILE
    if spec.exists():
        cmd = ["pyinstaller", str(spec), "--distpath", str(DIST), "--workpath", str(BUILD)]
    else:
        cmd = [
            "pyinstaller",
            "--onefile",
            "--name", "sentinel",
            "--distpath", str(DIST),
            "--workpath", str(BUILD),
            "--add-data", f"{ROOT / 'src' / 'sentinel' / 'dashboard_static'}:sentinel/dashboard_static",
            "--hidden-import", "sentinel.cli",
            "--hidden-import", "sentinel.snapshot",
            "--hidden-import", "sentinel.manifest",
            "--hidden-import", "sentinel.diff",
            "--hidden-import", "sentinel.policy",
            "--hidden-import", "sentinel.report",
            "--hidden-import", "sentinel.signing",
            "--hidden-import", "sentinel.incident",
            "--hidden-import", "sentinel.daemon",
            "--hidden-import", "sentinel.dashboard",
            "--hidden-import", "sentinel.defaults",
            str(ROOT / "src" / "sentinel" / "__main__.py"),
        ]

    subprocess.check_call(cmd, cwd=ROOT)

    # Find the built binary
    binary_name = "sentinel.exe" if platform.system() == "Windows" else "sentinel"
    binary_path = DIST / binary_name

    if not binary_path.exists():
        # PyInstaller may put it in a subdirectory
        for f in DIST.rglob(binary_name):
            if f.is_file():
                binary_path = f
                break

    if binary_path.exists():
        size = binary_path.stat().st_size
        print(f"✅ Built: {binary_path} ({size / 1024 / 1024:.1f} MB)")
        return binary_path
    else:
        print("❌ Build failed — binary not found.")
        sys.exit(1)


def create_archive(binary_path: Path) -> Path:
    """Create a compressed archive of the binary."""
    system = platform.system().lower()
    arch = platform.machine().lower()
    ext = ".zip" if system == "windows" else ".tar.gz"
    archive_name = f"sentinel-{system}-{arch}{ext}"
    archive_path = DIST / archive_name

    if system == "windows":
        import zipfile
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(binary_path, binary_path.name)
    else:
        import tarfile
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(binary_path, arcname=binary_path.name)

    print(f"✅ Archive: {archive_path}")
    return archive_path


if __name__ == "__main__":
    binary = build_binary()
    create_archive(binary)
