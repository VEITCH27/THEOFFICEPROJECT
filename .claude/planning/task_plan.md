# Sentinel — AI Model Runtime Integrity Checker

## Vision
A CLI tool that takes **pre/post checksums of system state** around AI model execution, and reports any unauthorized changes. It lets users answer: *"Did the AI model on my device change anything it shouldn't have?"*

## Phases

### Phase 1: Architecture & Project Structure ✅
- [x] Define core components
- [x] Create project layout
- [x] Set up packaging

### Phase 2: Core Snapshot Engine
- [ ] File integrity snapshot (SHA-256 of critical system paths)
- [ ] Process/daemon list capture
- [ ] Service state capture
- [ ] Network config snapshot
- [ ] Cron/timer/startup-item capture
- [ ] Serialize to signed manifest

### Phase 3: Diff Engine
- [ ] Load/compare two manifests
- [ ] Classify changes (new, modified, deleted)
- [ ] Handle expected changes gracefully

### Phase 4: Policy Engine
- [ ] Define safe change categories
- [ ] Track model working directory boundaries
- [ ] Flag out-of-bounds changes

### Phase 5: CLI Interface
- [ ] `sentinel snapshot` — take a snapshot
- [ ] `sentinel run` — execute command between snapshots
- [ ] `sentinel diff` — compare two snapshots
- [ ] `sentinel status` — check current state
- [ ] `sentinel allow` — whitelist expected changes

### Phase 6: Reporting
- [ ] Terminal output (rich/colored)
- [ ] JSON output for tooling
- [ ] HTML report

### Phase 7: Documentation
- [ ] README with examples
- [ ] Quickstart guide
- [ ] man page / --help

## Decisions
- **Name:** Sentinel
- **Language:** Python 3.10+ (no exotic deps — stdlib first, optional rich for display)
- **Hash:** SHA-256 by default, BLAKE2b as option
- **Output spec:** JSON manifest per snapshot, human-readable diff
- **Package:** pip-installable

## Errors
(none yet)
