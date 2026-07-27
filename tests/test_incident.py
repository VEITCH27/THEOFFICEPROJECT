"""Tests for the incident log module."""

import json
import tempfile
from pathlib import Path

import pytest

from sentinel.incident import (
    log_incident,
    list_incidents,
    get_incident,
    get_incident_stats,
    export_incidents,
    INCIDENT_LOG,
)


class TestIncidentLog:
    def setup_method(self):
        # Override path to temp location for test isolation
        self._orig_path = INCIDENT_LOG.expanduser()
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.test_log = self.tmp_dir / "incidents.jsonl"
        self._mock_path()

    def teardown_method(self):
        import sentinel.incident as inc
        inc.INCIDENT_LOG = self._orig_path
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _mock_path(self):
        import sentinel.incident as inc
        inc.INCIDENT_LOG = self.test_log
        inc.INCIDENT_INDEX = self.tmp_dir / "incidents_index.json"

    def test_log_and_list(self):
        record = log_incident(
            verdict="PASS — clean",
            severity_counts={"critical": 0, "suspicious": 0, "info": 0, "clear": 0},
            command="echo test",
            label="test_run",
            summary="clean run",
            findings_count=0,
        )
        assert "INC-0001" in record.get("id", "")
        assert record["verdict"] == "PASS — clean"

        incidents = list_incidents()
        assert len(incidents) == 1
        assert incidents[0]["id"] == record["id"]

    def test_multiple_incidents(self):
        for i in range(3):
            log_incident(
                verdict=f"PASS — run {i}",
                severity_counts={"critical": 0, "suspicious": 0, "info": 0, "clear": 0},
                command=f"cmd {i}",
                summary=f"run {i}",
                findings_count=0,
            )
        incidents = list_incidents()
        assert len(incidents) == 3
        # Newest first
        assert incidents[0]["verdict"] == "PASS — run 2"

    def test_get_incident_by_id(self):
        log_incident(
            verdict="WARNING — suspicious",
            severity_counts={"critical": 0, "suspicious": 2, "info": 0, "clear": 0},
            command="test",
            summary="suspicious activity",
            findings_count=2,
        )
        inc = get_incident("INC-0001")
        assert inc is not None
        assert "WARNING" in inc["verdict"]

    def test_get_incident_not_found(self):
        assert get_incident("INC-9999") is None

    def test_incident_stats(self):
        log_incident(
            verdict="FAIL — critical",
            severity_counts={"critical": 1, "suspicious": 0, "info": 0, "clear": 0},
            command="test",
            summary="critical",
            findings_count=1,
        )
        log_incident(
            verdict="PASS — clean",
            severity_counts={"critical": 0, "suspicious": 0, "info": 0, "clear": 0},
            command="test",
            summary="clean",
            findings_count=0,
        )
        stats = get_incident_stats()
        assert stats["total"] >= 2

    def test_export_json(self):
        log_incident(
            verdict="PASS",
            severity_counts={"critical": 0, "suspicious": 0, "info": 0, "clear": 0},
            command="test",
            summary="test",
            findings_count=0,
        )
        exported = export_incidents(format="json")
        data = json.loads(exported)
        assert isinstance(data, list)
        assert len(data) >= 1
