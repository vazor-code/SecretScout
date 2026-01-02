# 🕵️‍♂️🔐 SecretScout

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=30&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=800&height=80&lines=Stop+secrets+before+they+commit;Scan.+Block.+Commit;Because+oops+is+not+a+security+strategy" alt="SecretScout Slogan">
</p>

<p align="center">
  <b>Defensive secret scanning for Git repositories</b><br>
  <em>Catch tokens, keys & passwords before they leak into your Git history</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/Security-Defensive-purple?style=flat-square" alt="Defensive Security">
  <img src="https://img.shields.io/badge/CLI-Rich%20Reports-orange?style=flat-square" alt="Rich Reports">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-pre-commit">Pre-commit</a> •
  <a href="#-ci--sarif">CI/SARIF</a>
</p>

---

## 🌟 Why SecretScout?

> **One leaked token can compromise an entire environment.**  
> SecretScout is your last line of defense *before* secrets get committed.

Unlike reactive scanners that alert you after the damage is done, SecretScout is built for **prevention-first workflows**:

- 🔒 **Pre-commit protection** — scan staged changes before commit
- 🧼 **Clean Git history** — avoid painful “oops, rotate keys” moments
- ⚡ **Fast** — multi-thread scanning + caching
- 🎨 **Clear reporting** — redacted output, severity levels, actionable context
- 🧩 **CI-friendly** — JSON / SARIF / HTML outputs

---

## 🚀 Quick Start

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

### Initialize in your project

```bash
secretscout init .
```

### Scan your repository

```bash
# Scan git-tracked files (default)
secretscout scan .

# Scan everything under the folder
secretscout scan . --all

# Scan only staged changes (perfect for pre-commit)
secretscout scan --staged --format minimal --fail-on high
```

### Test it out (safe demo)

```bash
echo "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" > test_leak.txt
secretscout scan . --all
rm test_leak.txt  # Windows: del test_leak.txt
```

---

## ✨ Features

### 🔍 Detection (rules + heuristics)

SecretScout identifies common secret patterns:

* **Provider tokens:** GitHub (`ghp_...`), Google (`AIza...`), Slack, Telegram, etc.
* **Generic assignments:** `password=...`, `api_key: ...`, `token=...`
* **High-entropy strings** (token-like heuristics)
* **Private key headers** (PEM)

### ⚡ Performance

* **Multi-thread scanning**
* **Smart cache** to skip unchanged files
* **Git-aware modes**: tracked / staged / all

### 🎨 Reporting

* Pretty **Rich table** output (default)
* Minimal output for hooks/CI
* Machine formats: **JSON / SARIF / HTML**
* **Redaction**: secrets are never printed in full

### 🛡️ Prevention-first workflow

* Pre-commit ready (`--staged`)
* Baseline mode (ignore legacy findings)
* Flexible ignore patterns + inline suppressions
* Severity thresholds (`--fail-on`)

---

## 🧰 Usage

### Formats

```bash
secretscout scan . --format table
secretscout scan . --format minimal
secretscout scan . --format json  --output secretscout.json
secretscout scan . --format sarif --output secretscout.sarif
secretscout scan . --format html  --output secretscout_report.html
```

### Baseline (ignore known findings)

```bash
secretscout baseline . --output .secretscout.baseline.json
secretscout scan . --baseline .secretscout.baseline.json
```

### Rules (inspect)

```bash
secretscout rules list
secretscout rules show github-token
```

---

## 🧷 Pre-commit

Pre-commit runs checks automatically on `git commit`.

```bash
pip install pre-commit
pre-commit install
```

Run hooks manually:

```bash
pre-commit run --all-files
```

> The default hook configuration uses `--staged` by design: it scans exactly what will be committed.

---

## 🤖 CI & SARIF

Generate SARIF locally:

```bash
secretscout scan . --format sarif --output secretscout.sarif
```

Upload SARIF in GitHub Actions (snippet):

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: |
    pip install -e .
    secretscout scan . --format sarif --output secretscout.sarif --fail-on high || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secretscout.sarif
```

View results:
**Repo → Security → Code scanning alerts**

---

## ⚙️ Configuration

SecretScout uses TOML + ignore file:

* `.secretscout.toml` — configuration
* `.secretscoutignore` — glob ignore patterns
* `.secretscout-cache/` — cache (do not commit)

Example `.secretscout.toml`:

```toml
[scan]
max_file_size = 1048576
exclude = [".git/**", ".venv/**", "node_modules/**", "dist/**", "build/**", ".secretscout-cache/**"]
threads = 8
first_lines_ignore_file_marker = 5

[report]
fail_on = "high"
max_findings = 200
redact_head = 4
redact_tail = 4

[rules]
disable = []
allowlist = ["(?i)example_token", "(?i)dummy_key", "(?i)changeme"]
path_allowlist = ["(^|/)tests?/fixtures(/|$)"]
```

### Ignoring findings

Ignore a file (must appear within first N lines):

```python
# secretscout:ignore-file
```

Ignore a single line:

```python
token = "ghp_..."  # secretscout:ignore
```

---

## ✅ Exit Codes

* `0` — no findings at/above `--fail-on`
* `1` — findings at/above `--fail-on`
* `2` — runtime error

---

## 🛡️ Security Philosophy

* **Offline by default** — no network calls required
* **Redaction** — secrets are never printed fully
* **Defensive tooling** — helps prevent accidental exposure

---

## 🤝 Contributing

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

---

## 📄 License

MIT

<p align="center">
  <b>Made for secure development workflows</b><br>
  <sub>SecretScout — because prevention beats remediation.</sub>
</p>
