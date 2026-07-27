"""Shared fixtures for Sentinel tests."""

import pytest


# Allow test modules to import from sentinel package
pytest.register_assert_rewrite("tests")
