"""Tests for the diff engine."""

import json

from sentinel.diff import (
    diff_files,
    diff_processes,
    diff_services,
    full_diff,
    classify_path,
)


def _make_snapshot(
    files: dict = None,
    processes: dict = None,
    services: dict = None,
    cron: dict = None,
    network: dict = None,
    kernel: dict = None,
    label: str = "test",
):
    return {
        "meta": {"label": label, "timestamp": "2025-01-01T00:00:00", "manifest_hash": ""},
        "files": files or {"critical": {}, "suspicious": {}, "user_config": {}, "extra": {}},
        "processes": processes or {},
        "services": services or {},
        "cron": cron or {"system": [], "users": {}},
        "network": network or {},
        "kernel": kernel or {},
    }


class TestDiffFiles:
    def test_no_changes(self):
        pre = _make_snapshot(files={"critical": {"/etc/hosts": {"sha256": "abc", "size": 100}}})
        post = _make_snapshot(files={"critical": {"/etc/hosts": {"sha256": "abc", "size": 100}}})
        result = diff_files(pre, post)
        assert len(result["added"]) == 0
        assert len(result["removed"]) == 0
        assert len(result["modified"]) == 0
        assert result["unchanged_count"] == 1

    def test_file_added(self):
        pre = _make_snapshot(files={"critical": {}})
        post = _make_snapshot(files={"critical": {"/etc/new_file": {"sha256": "abc", "size": 10}}})
        result = diff_files(pre, post)
        assert len(result["added"]) == 1
        assert result["added"][0]["path"] == "/etc/new_file"

    def test_file_removed(self):
        pre = _make_snapshot(files={"critical": {"/etc/old_file": {"sha256": "abc", "size": 10}}})
        post = _make_snapshot(files={"critical": {}})
        result = diff_files(pre, post)
        assert len(result["removed"]) == 1
        assert result["removed"][0]["path"] == "/etc/old_file"

    def test_file_modified(self):
        pre = _make_snapshot(files={"critical": {"/etc/hosts": {"sha256": "abc", "size": 100}}})
        post = _make_snapshot(files={"critical": {"/etc/hosts": {"sha256": "def", "size": 200}}})
        result = diff_files(pre, post)
        assert len(result["modified"]) == 1
        assert result["modified"][0]["pre_sha256"] == "abc"
        assert result["modified"][0]["post_sha256"] == "def"


class TestDiffProcesses:
    def test_new_processes(self):
        pre = _make_snapshot(processes={"1": {"pid": 1, "name": "init"}})
        post = _make_snapshot(processes={"1": {"pid": 1, "name": "init"}, "100": {"pid": 100, "name": "python3"}})
        result = diff_processes(pre, post)
        assert result["new_count"] == 1
        assert result["new"][0]["name"] == "python3"

    def test_gone_processes(self):
        pre = _make_snapshot(processes={"1": {"pid": 1, "name": "init"}, "100": {"pid": 100, "name": "python3"}})
        post = _make_snapshot(processes={"1": {"pid": 1, "name": "init"}})
        result = diff_processes(pre, post)
        assert result["gone_count"] == 1

    def test_filter_volatile_processes(self):
        # kworker processes should be filtered out
        pre = _make_snapshot(processes={"1": {"name": "init"}})
        post = _make_snapshot(processes={"1": {"name": "init"}, "42": {"name": "kworker/0:0"}})
        result = diff_processes(pre, post)
        assert result["new_count"] == 0


class TestDiffServices:
    def test_no_service_changes(self):
        pre = _make_snapshot(services={"sshd.service": {"active": "active"}})
        post = _make_snapshot(services={"sshd.service": {"active": "active"}})
        result = diff_services(pre, post)
        assert result["changed_count"] == 0

    def test_service_state_change(self):
        pre = _make_snapshot(services={"sshd.service": {"active": "active"}})
        post = _make_snapshot(services={"sshd.service": {"active": "inactive"}})
        result = diff_services(pre, post)
        assert result["changed_count"] == 1
        assert result["changed"][0]["pre"] == "active"
        assert result["changed"][0]["post"] == "inactive"


class TestClassifyPath:
    def test_critical_path(self):
        assert classify_path("/etc/ssh/sshd_config") == "critical"

    def test_unknown_path(self):
        assert classify_path("/opt/custom/file") == "monitored"


class TestFullDiff:
    def test_full_diff_structure(self):
        pre = _make_snapshot(label="pre")
        post = _make_snapshot(label="post")
        result = full_diff(pre, post)
        assert result["pre_label"] == "pre"
        assert result["post_label"] == "post"
        assert "files" in result
        assert "processes" in result
        assert "services" in result
        assert "cron" in result
        assert "network" in result
        assert "kernel" in result
        assert "manifest_hash_match" in result
