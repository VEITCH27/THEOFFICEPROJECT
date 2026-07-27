# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Sentinel standalone binary."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src" / "sentinel" / "dashboard_static"

a = Analysis(
    [str(ROOT / "src" / "sentinel" / "__main__.py")],
    pathex=[],
    binaries=[],
    datas=[
        (str(STATIC / "styles.css"), "sentinel/dashboard_static"),
        (str(STATIC / "app.js"), "sentinel/dashboard_static"),
    ],
    hiddenimports=[
        "sentinel.cli",
        "sentinel.snapshot",
        "sentinel.manifest",
        "sentinel.diff",
        "sentinel.policy",
        "sentinel.report",
        "sentinel.signing",
        "sentinel.incident",
        "sentinel.daemon",
        "sentinel.dashboard",
        "sentinel.defaults",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "unittest",
        "test",
        "distutils",
        "setuptools",
        "pip",
        "pydoc",
        "email",
        "http",
        "xml",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
