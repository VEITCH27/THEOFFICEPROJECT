"""Tests for the signing module."""

import json
import tempfile
from pathlib import Path

from sentinel.signing import _gpg_available, _get_default_key, verify_manifest


class TestSigning:
    def test_gpg_available(self):
        """GPG may or may not be available, handle both."""
        available = _gpg_available()
        # Just check it returns bool without error
        assert isinstance(available, bool)

    def test_get_default_key(self):
        """May return None if no key exists, or a string."""
        key = _get_default_key()
        assert key is None or isinstance(key, str)

    def test_verify_no_signature(self):
        """Verify a manifest with no signature file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": "data"}, f)
            path = Path(f.name)
        try:
            valid, details = verify_manifest(path)
            assert valid is False
            assert "No signature" in details or "not found" in details
        finally:
            path.unlink()
