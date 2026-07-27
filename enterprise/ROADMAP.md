# Sentinel Enterprise — Product Roadmap

> **Model:** Open Core (MIT) + Enterprise License
> **CLI:** Free forever, MIT licensed
> **Enterprise:** Subscription-based, per-node or per-seat pricing

---

## Tier Overview

| Feature | Free (CLI) | Pro ($99/mo) | Enterprise (Custom) |
|---------|-----------|-------------|-------------------|
| `sentinel run` | ✅ | ✅ | ✅ |
| `sentinel snapshot` | ✅ | ✅ | ✅ |
| `sentinel dashboard` | ✅ (local) | ✅ (local) | ✅ (multi-user) |
| `sentinel daemon` | ✅ (single-host) | ✅ (multi-host) | ✅ (multi-host) |
| GPG signing | ✅ | ✅ | ✅ |
| Allowlist | ✅ | ✅ | ✅ |
| Incident log | ✅ (local JSONL) | ✅ (centralized) | ✅ (centralized) |
| **Multi-host monitoring** | — | ✅ (up to 10) | ✅ (unlimited) |
| **Central dashboard** | — | ✅ (cloud-hosted) | ✅ (self-hosted + cloud) |
| **Team RBAC** | — | ✅ (3 users) | ✅ (unlimited + SSO) |
| **Slack / PagerDuty / Webhook alerts** | — | ✅ | ✅ |
| **Compliance reports** | — | — | ✅ (SOC 2, ISO 27001, HIPAA) |
| **Policy-as-code** | — | — | ✅ (YAML/JSON policy files) |
| **SAML / OIDC SSO** | — | — | ✅ |
| **Audit export (CSV, PDF, Splunk)** | — | ✅ | ✅ |
| **Custom retention** | 30 days | 90 days | 1 year+ |
| **Support** | GitHub Issues | Email (4hr SLA) | Slack + Email (1hr SLA) |
| **On-prem / air-gapped** | — | — | ✅ |
| **SIEM integration** (Splunk, Datadog, Sentinel) | — | — | ✅ |

---

## Phase 1: Foundation (Now — CLI is here)

**Goal:** Get users, validate the need, build community.

- ✅ CLI with 11 subcommands (MIT)
- ✅ PyPI package: `model-integrity-cli`
- 🚧 Docker image on GHCR
- 🚧 Homebrew formula
- ⬜ GitHub Actions CI template (`.github/workflows/sentinel-check.yml`)
- ⬜ Pre-built binaries for macOS, Linux, Windows (PyInstaller or Nuitka)
- ⬜ `brew install model-integrity-cli` in homebrew/core
- ⬜ Website: `modelintegrity.dev` with docs + demo
- ⬜ "Show HN" launch
- ⬜ Product Hunt launch

**Success metric:** 500 GitHub stars, 1000 pip installs/month, 5 posts on social media

---

## Phase 2: Pro ($99/mo — 2-3 months after launch)

**Goal:** First revenue — serve small teams and startups.

### Central Dashboard (cloud-hosted)

```
┌──────────────────────────────────────────────┐
│  Sentinel Cloud Dashboard                     │
│                                              │
│  ┌──────┬──────┬──────┬──────┐               │
│  │ Nodes│ Alerts│ Pass │ Fail │               │
│  │  12  │   3   │  89% │  11% │               │
│  └──────┴──────┴──────┴──────┘               │
│                                              │
│  Host          │ Status │ Last Check │ Verdict│
│  ──────────────────────────────────────────  │
│  prod-llama-1  │ 🟢     │ 2m ago     │ PASS  │
│  prod-llama-2  │ 🟡     │ 5m ago     │ WARN  │
│  staging-1     │ 🔴     │ 10m ago    │ FAIL  │
│  dev-box       │ 🟢     │ 1m ago     │ PASS  │
└──────────────────────────────────────────────┘
```

### What it needs:

| Component | Implementation |
|-----------|---------------|
| **Backend API** | FastAPI + SQLite/Postgres — receives snapshot uploads from CLI |
| **CLI upload** | `sentinel push` — send local snapshot to cloud |
| **Dashboard** | Same as local dashboard but multi-tenant, cloud-hosted |
| **Auth** | Magic-link email login, GitHub OAuth |
| **Multi-host** | Register multiple machines, view in one place |
| **Alerts** | Slack webhook, email notifications on FAIL verdict |

### Pricing

```
Pro:  $99/mo  — up to 10 nodes, 3 users, 90-day retention
      $499/mo — up to 50 nodes, 10 users, unlimited retention
```

---

## Phase 3: Enterprise (custom pricing — 6 months after launch)

**Goal:** Real revenue — serve compliance-driven companies.

### Feature: Policy-as-Code

YAML file that defines exactly what's allowed:

```yaml
# sentinel.policy.yaml
version: "1.0"

model_dirs:
  - /models/**
  - /data/models/**

allowed_changes:
  # Model working dir — expected
  - path: /models/**
    severity: info

  # Temp files — expected
  - path: /tmp/**
    severity: clear

  # Logs — expected
  - path: /var/log/sentinel/**
    severity: clear

blocked_changes:
  # Never allow cron changes
  - path: /etc/cron*/**
    severity: critical
    action: alert + block

  # Never allow network config changes
  - path: /etc/iptables*
    severity: critical
    action: alert + block

compliance:
  standards:
    - soc2
    - iso_27001
    - hipaa
  report_frequency: weekly
  report_recipients:
    - security@company.com
```

### Feature: Compliance Reports

Auto-generated PDF/CSV reports mapping Sentinel results to compliance controls:

| Standard | Control | Sentinel Mapping |
|----------|---------|-----------------|
| SOC 2 | CC6.1 — Logical Access | Snapshot manifests + GPG signatures |
| SOC 2 | CC7.1 — Monitoring | Daemon mode + incident log |
| ISO 27001 | A.12.6.1 — Event Logging | Incident audit trail |
| ISO 27001 | A.12.4.1 — Protection of Log Info | Signed manifests |
| HIPAA | 45 CFR §164.312(b) — Audit Controls | Full history + export |
| NIST 800-53 | AU-2 — Event Types | All system state changes |

### Feature: SIEM Integration

Push verdicts to existing security infrastructure:

```
Sentinel → Splunk HEC → Splunk dashboard
Sentinel → Datadog Logs → Datadog monitor
Sentinel → Azure Sentinel → Azure workbook
Sentinel → AWS Security Hub → AWS findings
```

### Feature: SSO / Enterprise Auth

- SAML 2.0 (Okta, Azure AD, Google Workspace)
- OIDC (any OpenID provider)
- SCIM provisioning (auto-add/remove users)

### Pricing

```
Enterprise: $5,000/yr — up to 25 nodes
            $15,000/yr — up to 100 nodes
            Custom     — unlimited nodes + on-prem
```

---

## Phase 4: Platform (12+ months)

**Goal:** Become the standard for AI model runtime security.

### What this looks like

- **Agent SDK** — embed Sentinel directly into model runners (Ollama plugin, vLLM plugin, Llama.cpp integration)
- **GitHub App** — auto-check every model push in CI
- **VS Code extension** — see integrity status while developing models
- **Marketplace listing** — AWS Marketplace, Azure Marketplace (easier enterprise procurement)
- **Managed offering** — "Sentinel as a Service" — fully managed, zero-config

---

## Development Estimates

| Feature | Effort | Complexity |
|---------|--------|-----------|
| Docker image + CI | ✅ Done | Low |
| Homebrew formula | ✅ Done | Low |
| Pre-built binaries | 2 days | Low |
| `sentinel push` command | 3 days | Medium |
| Cloud dashboard backend | 2 weeks | Medium |
| Multi-host management | 1 week | Medium |
| Slack/email alerts | 3 days | Low |
| Policy-as-code | 1 week | Medium |
| Compliance reports | 2 weeks | High |
| SSO/SAML | 1 week | Medium |
| SIEM integration | 1 week | Medium |

---

## Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Companies don't care about runtime integrity | Medium | Validate via Phase 1 community before building paid features |
| Competitor emerges (HiddenLayer adds runtime checks) | Medium | First-mover advantage + open-source community |
| Enterprise sales cycle is slow | High | Start with Pro ($99/mo self-serve) before enterprise |
| Python dependency limits adoption | Medium | Offer pre-built binaries, then rewrite core in Rust/Go if needed |
