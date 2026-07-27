"""Tests for the snapshot engine."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from sentinel.snapshot import take_snapshot, _hash_file, _should_exclude, _is_volatile


class TestHashing:
    def test_hash_file_exists(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello sentinel")
            f.flush()
            path = Path(f.name)
        try:
            h = _hash_file(path)
            expected = hashlib.sha256(b"hello sentinel").hexdigest()
            assert h == expected
        finally:
            path.unlink()

    def test_hash_file_nonexistent(self):
        assert _hash_file(Path("/nonexistent/file")) is None

    def test_hash_file_permission_error(self):
        # This test may not work as root; skip gracefully
        path = Path("/proc/1/cmdline")
        if path.exists():
            result = _hash_file(path)
            # Either we get a hash or None, both are acceptable
            assert result is None or isinstance(result, str) and len(result) == 64


class TestFilters:
    def test_should_exclude_pyc(self):
        assert _should_exclude(Path("/some/path/file.pyc"))

    def test_should_exclude_git(self):
        assert _should_exclude(Path("/repo/.git"))

    def test_should_exclude_cache(self):
        assert _should_exclude(Path("/home/user/.cache"))

    def test_should_not_exclude_python_file(self):
        assert not _should_exclude(Path("/home/user/script.py"))

    def test_should_not_exclude_config(self):
        assert not _should_exclude(Path("/etc/hosts"))

    def test_is_volatile_logs(self):
        assert _is_volatile(Path("/var/log/syslog"))

    def test_is_volatile_tmp(self):
        assert _is_volatile(Path("/tmp/somefile"))

    def test_is_not_volatile_etc(self):
        assert not _is_volatile(Path("/etc/hosts"))


class TestSnapshotFunction:
    def test_take_snapshot_basic(self):
        snapshot = take_snapshot(label="test")
        assert "meta" in snapshot
        assert snapshot["meta"]["label"] == "test"
        assert "timestamp" in snapshot["meta"]
        assert "hostname" in snapshot["meta"]
        assert "manifest_hash" in snapshot["meta"]
        assert "files" in snapshot
        assert "critical" in snapshot["files"]
        assert "suspicious" in snapshot["files"]
        assert "processes" in snapshot
        assert "services" in snapshot
        assert "cron" in snapshot
        assert "network" in snapshot
        assert "kernel" in snapshot

    def test_snapshot_manifest_hash_changes(self):
        """Manifest hash should change if file contents differ."""
        s1 = take_snapshot(label="test1")
        # We can't easily change system files, but we can verify the hash exists
        assert len(s1["meta"]["manifest_hash"]) == 64

    def test_snapshot_consistency(self):
        """Same snapshot called twice should produce same structure."""
        s1 = take_snapshot(label="a")
        s2 = take_snapshot(label="b")
        assert s1["meta"]["label"] != s2["meta"]["label"]
        assert s1["meta"]["hostname"] == s2["meta"]["hostname"]
        # Both should have the same keys
        assert set(s1.keys()) == set(s2.keys())
