"""Tests for the policy engine."""

from sentinel.policy import (
    evaluate_diff,
    add_to_allowlist,
    remove_from_allowlist,
    _load_allowlist,
    SEVERITY_CLEAR,
    SEVERITY_INFO,
    SEVERITY_SUSPICIOUS,
    SEVERITY_CRITICAL,
)


def _make_diff(files_changes: dict = None, procs: dict = None,
               svcs: dict = None, cron: dict = None,
               net: dict = None, kernel: dict = None):
    return {
        "pre_label": "pre",
        "post_label": "post",
        "pre_timestamp": "",
        "post_timestamp": "",
        "manifest_hash_match": True,
        "files": files_changes or {"added": [], "removed": [], "modified": [], "unchanged_count": 0},
        "processes": procs or {"new": [], "gone": [], "new_count": 0, "gone_count": 0},
        "services": svcs or {"changed": [], "changed_count": 0},
        "cron": cron or {"changes": [], "change_count": 0},
        "network": net or {},
        "kernel": kernel or {},
    }


class TestEvaluateDiff:
    def test_no_changes_pass(self):
        diff = _make_diff()
        result = evaluate_diff(diff)
        assert "PASS" in result["verdict"]
        assert result["counts"]["critical"] == 0
        assert result["counts"]["suspicious"] == 0

    def test_critical_file_change(self):
        diff = _make_diff(
            files_changes={
                "added": [{"path": "/etc/ssh/new_key", "category": "critical", "volatile": False}],
                "removed": [],
                "modified": [],
                "unchanged_count": 0,
            }
        )
        result = evaluate_diff(diff)
        assert result["counts"]["critical"] > 0
        assert "FAIL" in result["verdict"]

    def test_suspicious_config_change(self):
        diff = _make_diff(
            files_changes={
                "added": [],
                "removed": [],
                "modified": [{"path": "/etc/hosts", "category": "suspicious", "volatile": False}],
                "unchanged_count": 0,
            }
        )
        result = evaluate_diff(diff)
        assert "WARNING" in result["verdict"]

    def test_model_dir_change_is_info(self):
        diff = _make_diff(
            files_changes={
                "added": [{"path": "/home/user/models/llama/output.bin", "category": "extra", "volatile": False}],
                "removed": [],
                "modified": [],
                "unchanged_count": 0,
            }
        )
        result = evaluate_diff(diff, model_dirs=["/home/user/models/llama"])
        # File inside model dir is INFO
        info_evals = [e for e in result["evaluations"] if e["severity"] == SEVERITY_INFO]
        assert len(info_evals) > 0

    def test_cron_change_is_critical(self):
        diff = _make_diff(
            cron={
                "changes": [{"type": "system_cron", "file": "/etc/cron.d/malicious", "changed": True}],
                "change_count": 1,
            }
        )
        result = evaluate_diff(diff)
        assert result["counts"]["critical"] > 0
        assert "FAIL" in result["verdict"]

    def test_firewall_change_is_critical(self):
        diff = _make_diff(net={"firewall_changed": True})
        result = evaluate_diff(diff)
        assert result["counts"]["critical"] > 0

    def test_new_process_is_info(self):
        diff = _make_diff(procs={"new": [{"pid": 1234, "name": "python3"}], "gone": [],
                                  "new_count": 1, "gone_count": 0})
        result = evaluate_diff(diff)
        info_evals = [e for e in result["evaluations"] if e["severity"] == SEVERITY_INFO]
        assert len(info_evals) > 0


class TestAllowlist:
    def test_add_and_remove(self):
        path = "/test/allowlist/path"
        add_to_allowlist(path)
        allowlist = _load_allowlist()
        assert path in allowlist

        remove_from_allowlist(path)
        allowlist = _load_allowlist()
        assert path not in allowlist

    def test_allowlist_clears_severity(self):
        path = "/etc/critical/test"
        add_to_allowlist(path)
        diff = _make_diff(
            files_changes={
                "modified": [{"path": path, "category": "critical", "volatile": False}],
                "added": [],
                "removed": [],
                "unchanged_count": 0,
            }
        )
        result = evaluate_diff(diff)
        # Allowlisted paths should have CLEAR severity
        allowlisted_evals = [e for e in result["evaluations"] if e["severity"] == SEVERITY_CLEAR]
        assert len(allowlisted_evals) > 0
        # Clean up
        remove_from_allowlist(path)
