# Sentinel — Launch Checklist

> Use this to track what's done and what's next for the public launch.

---

## ✅ Done

| Item | Status | Notes |
|------|--------|-------|
| CLI with 11 subcommands | ✅ | MIT licensed |
| PyPI package | ✅ | `pip install model-integrity-cli` |
| 52 tests passing | ✅ | `python -m pytest tests/` |
| README with full docs | ✅ | Updated with all features |
| Docker image | ✅ | `docker/Dockerfile` + GHCR workflow |
| Homebrew formula | ✅ | `homebrew/model-integrity-cli.rb` |
| Enterprise roadmap | ✅ | `enterprise/ROADMAP.md` |
| CI/CD template | ✅ | `.github/workflows/sentinel-check.yml` |
| Release workflow | ✅ | `.github/workflows/release.yml` — auto-builds binaries for Linux/macOS/Windows |
| Build scripts | ✅ | `build/build.py` + `build/sentinel.spec` |
| CHANGELOG | ✅ | `CHANGELOG.md` |
| Issue templates | ✅ | Bug report + feature request |

---

## 🚧 Needs Action (by you)

| Item | Action |
|------|--------|
| **GitHub repo** | Create `model-integrity-cli/sentinel` on GitHub and push this code |
| **Tag v0.1.0** | `git tag v0.1.0 && git push origin v0.1.0` — triggers release workflow |
| **Homebrew core** | Open a PR to `Homebrew/homebrew-core` with the formula. Or keep it in your tap. |
| **Docker Hub** | Optional — also publish to `docker.io/model-integrity-cli/sentinel` (GHCR already set up) |
| **Website domain** | Register `modelintegrity.dev` or `model-integrity.dev` |
| **PyPI ownership** | Verify you can push future versions (`twine upload dist/*`) |

---

## 📢 Launch (recommended order)

| Step | Why |
|------|-----|
| **1. Push to GitHub + tag** | Everything flows from here — releases, Docker, CI |
| **2. "Show HN" post** | Biggest single source of early users. Title: *"Show HN: Sentinel – Check if an AI model modified your system"* |
| **3. Product Hunt** | Second wave. Schedule for a Tuesday/Wednesday morning |
| **4. Reddit** | Post to `r/netsec`, `r/machinelearning`, `r/devops` with a tutorial angle |
| **5. Blog post** | *"How I caught my local LLM trying to modify /etc/hosts"* — dramatic, shareable |
| **6. YouTube demo** | 2-3 min screen recording showing `sentinel run` in action |

---

## 📈 Growth Loops

- **GitHub Actions template** → any repo using it gets a `sentinel-check.yml` badge → discoverability
- **`sentinel run` output** includes a footer: *"Protected by Sentinel (MIT) — model-integrity-cli on PyPI"*
- **Docker pulls** → GHCR shows download counts → social proof
