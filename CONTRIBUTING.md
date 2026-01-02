# 🕵️‍♂️🔐 SecretScout — Contributing Guide

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=26&duration=3000&pause=900&color=00FF00&center=true&vCenter=true&width=900&height=70&lines=Contribute+to+SecretScout;Small+PRs.+Strong+Security.;Defensive+only.+No+real+secrets." alt="SecretScout Contributing">
</p>

<p align="center">
  <b>Help us build a prevention-first secret scanner</b><br>
  <em>Fast • Defensive • Offline-friendly • CI-ready</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Defensive%20Security-purple?style=flat-square" alt="Defensive Security">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Tests-pytest-blue?style=flat-square" alt="pytest">
  <img src="https://img.shields.io/badge/Lint-ruff-orange?style=flat-square" alt="ruff">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-workflow">Workflow</a> •
  <a href="#-rules--tests">Rules & Tests</a> •
  <a href="#-style--quality">Style & Quality</a> •
  <a href="#-pull-requests">Pull Requests</a>
</p>

---

## 🌟 Before You Start

> **SecretScout is defensive.**  
> Contributions must support secure development workflows and **must not** enable offensive behavior.

### ✅ Contribution Principles
- **No real secrets** in code, tests, docs, screenshots, or logs.
- **Offline-first**: avoid network calls/telemetry.
- **Redaction always**: never print full secret material.
- Prefer **small, focused PRs**.

### ❌ Do Not Submit
- “Real” tokens, keys, passwords, private key data  
- Code that exfiltrates, uploads, or reports repository contents  
- Anything that increases risk for users

---

## 🚀 Quick Start

### Requirements
- Python **3.10+**
- Git
- (Optional) `pre-commit`

### Install (from source / dev)
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

pip install -U pip
pip install -e ".[dev]"
````

### Run tests

```bash
pytest
```

### Run lint

```bash
ruff check .
```

### (Optional) Enable pre-commit

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

---

## 🔁 Workflow

### 1) Create a branch

```bash
git checkout -b feat/my-change
```

### 2) Make changes

Keep PRs small and readable.

### 3) Verify locally

```bash
ruff check .
pytest
```

### 4) Push and open a PR

```bash
git push -u origin feat/my-change
```

---

## 🧩 Rules & Tests

SecretScout detects secrets using **rules (regex + metadata)** and **heuristics**.

### Where things live

* `src/secretscout/cli.py` — CLI commands
* `src/secretscout/scanner.py` — core scanning
* `src/secretscout/rules.py` — built-in rules
* `src/secretscout/reporting.py` — table/json/sarif/html
* `src/secretscout/config.py` — TOML + defaults
* `tests/` — unit tests

### Adding or updating a rule

When you add a rule:

* Give it a stable `id` (kebab-case)
* Add a clear `title` and appropriate `severity`
* Keep regex specific to reduce false positives
* Add tests for:

  * ✅ positive detection
  * ✅ allowlist behavior (if relevant)
  * ✅ ignore markers behavior (line/file)

### Dummy secrets (safe examples)

Use placeholders only:

* GitHub: `ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
* Generic: `token=example_token_123`
* Private key headers with dummy content (never real key bytes)

---

## 🎨 Style & Quality

### Code style

* Keep functions small and well-named
* Avoid hidden side effects
* Prefer deterministic behavior (stable results for baseline use)

### Performance

* Avoid reading huge files unnecessarily
* Respect `max_file_size`
* Prefer streaming / efficient operations when possible

### Security

* Never print full secrets
* Prefer redaction everywhere
* Avoid storing findings beyond what’s needed for the report

---

## ✅ Pull Requests

### PR checklist

Before opening a PR, ensure:

* [ ] `pytest` passes
* [ ] `ruff check .` passes
* [ ] New behavior includes tests
* [ ] No real secrets anywhere
* [ ] README/docs updated if you changed CLI behavior or config

### PR description (recommended)

Include:

* What changed (bullet points)
* Why it changed
* How to test
* Any trade-offs / known limitations

---

## 🐛 Bug Reports

When filing an issue, include:

* OS + Python version
* Exact command you ran (`secretscout scan ...`)
* Expected vs actual behavior
* Minimal repro (no real secrets)

Helpful info:

```bash
python --version
secretscout --version
secretscout scan . --format minimal
```

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the **MIT License**.

<p align="center">
  <b>Thanks for helping make SecretScout better ❤️</b><br>
  <sub>Small PRs. Strong security. Clean Git history.</sub>
</p>
