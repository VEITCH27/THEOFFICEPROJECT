# Progress Log

## Session 1 — 2026-07-27

### Phase 1: Architecture & Project Structure ✅
- Created project layout under `/home/user/.workspace/projects/sentinel/`
- Set up pyproject.toml with hatchling build
- Created planning files
- Package name: `sentinel`

### Phase 2: Core Snapshot Engine ✅
- `snapshot.py` — file hashing (SHA-256), process/daemon capture, systemd services, cron, network config, kernel state
- `defaults.py` — categorized system paths (critical, suspicious), exclusion filters, volatility detection
- `manifest.py` — JSON serialization with rolling content hash

### Phase 3: Diff Engine ✅
- `diff.py` — full comparison across files, processes, services, cron, network, kernel
- Filters volatile kernel threads from process diffs
- Detects added/removed/modified files

### Phase 4: Policy Engine ✅
- `policy.py` — severity classification engine
- Allowlist management (persistent JSON file)
- Model working directory boundaries
- Per-change-type severity mapping

### Phase 5: CLI ✅
- `cli.py` — 6 subcommands: snapshot, run, diff, list, allow, status
- `--format terminal|json` output selection
- Exit codes: 0 clean, 1 warning, 2 critical

### Phase 6: Reporting ✅
- `report.py` — colored terminal output with severity badges, JSON output
- Shows breakdown by severity, file summary, process changes

### Phase 7: Tests & Docs ✅
- 43 tests across 4 test files — all passing
- Comprehensive README with usage examples, architecture overview, integration ideas

### Errors
- CLI test failure: argparse `command` positional arg name conflicted with subparser `dest`. Fixed by renaming to `cmd`.
- Diff process test failure: mock data missing `pid` field in process dict. Added field.
