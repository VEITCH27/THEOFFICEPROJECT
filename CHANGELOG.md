# Changelog

## v0.1.0 (2026-07-27)

### Initial Release

**CLI Commands (11):**
- `sentinel run` — wrap model execution with pre/post integrity snapshots
- `sentinel snapshot` — take a standalone system state snapshot
- `sentinel diff` — compare two existing snapshots
- `sentinel list` — list saved snapshots
- `sentinel allow` — manage the allowlist
- `sentinel status` — quick system overview
- `sentinel sign` — GPG-sign a manifest
- `sentinel verify` — verify a GPG-signed manifest
- `sentinel daemon` — background drift detection daemon
- `sentinel dashboard` — local web-based GUI
- `sentinel incidents` — audit trail viewer

**Core Engine:**
- SHA-256 file integrity hashing for critical system paths
- System state capture: processes, systemd services, cron, network config, kernel modules
- Difference engine with severity classification (critical/suspicious/info/clear)
- Policy engine with model working directory boundaries and allowlist
- Zero external dependencies — pure Python 3.10+ stdlib

**Publishing:**
- PyPI: `pip install model-integrity-cli`
- Docker: `ghcr.io/model-integrity-cli/sentinel`
- Homebrew: `brew install model-integrity-cli`
- MIT License — open core

**Tests:** 52/52 passing
