"""Default paths, categories, and configuration for Sentinel."""

from pathlib import Path

# ── Default system paths to monitor ──────────────────────────────────────

# Directories monitored at the CRITICAL level — any change is a red flag
CRITICAL_PATHS = [
    Path("/etc"),
    Path("/etc/ssh"),
    Path("/etc/systemd"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/etc/pam.d"),
    Path("/etc/sudoers.d"),
    Path("/etc/security"),
    Path("/etc/apt/sources.list.d"),
    Path("/etc/iptables"),
    Path("/etc/nftables.conf"),
]

# Directories monitored at the SUSPICIOUS level
SUSPICIOUS_PATHS = [
    Path("/etc/default"),
    Path("/etc/profile.d"),
    Path("/etc/xdg"),
    Path("/etc/NetworkManager"),
    Path("/etc/hosts"),
    Path("/etc/hostname"),
    Path("/etc/resolv.conf"),
    Path("/etc/environment"),
]

# User-level startup/config files
USER_CONFIG_PATHS = [
    "~/.bashrc",
    "~/.bash_profile",
    "~/.zshrc",
    "~/.config/autostart",
    "~/.config/systemd/user",
    "~/.ssh/authorized_keys",
    "~/.profile",
    "~/.local/share/applications",
]

# ── Exclusions (patterns to skip during file walking) ────────────────────

EXCLUDE_GLOBS = [
    "*.pyc",
    "__pycache__",
    ".git",
    ".cache",
    "*.swp",
    "*.swx",
    "*.tmp",
    "*.log",
    "*.pid",
    "*.lock",
]

# ── Default snapshot storage ─────────────────────────────────────────────

SENTINEL_DIR = Path("~/.sentinel").expanduser()
MANIFEST_DIR = SENTINEL_DIR / "manifests"
POLICY_FILE = SENTINEL_DIR / "policy.json"
ALLOW_LIST_FILE = SENTINEL_DIR / "allowlist.json"

# ── Known-safe patterns (system noise that changes legitimately) ─────────

# Path substrings that indicate expected volatility
VOLATILE_PATTERNS = [
    "/var/log",
    "/var/cache",
    "/var/tmp",
    "/tmp",
    ".cache",
    "browser-cache",
    "thumbnails",
    "Trash",
    "recently-used",
]

# Process patterns that rotate PIDs each run
VOLATILE_PROCESS_PATTERNS = [
    "kworker",
    "kthreadd",
    "watchdog",
    "migration",
    "rcu",
    "irq",
]
