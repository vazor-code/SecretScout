---
name: "\U0001F41B Bug report"
about: Report a bug or unexpected behavior in SecretScout
title: "[BUG] "
labels: bug
assignees: ''

---

## 🐞 Bug description

**Describe the bug clearly and concisely.**  
What went wrong? What did you expect instead?

---

## 🔁 Steps to reproduce

Steps to reproduce the behavior:

1. Run command:
```bash
   secretscout scan .
```

2. Use configuration:

   * `.secretscout.toml`: yes / no
   * `.secretscoutignore`: yes / no
3. See error / unexpected output

> ⚠️ **Do not include real secrets.**
> Use dummy values only (e.g. `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`).

---

## ✅ Expected behavior

A clear and concise description of what you expected to happen.

---

## ❌ Actual behavior

What actually happened?
Include error messages, incorrect output, or unexpected results.

---

## 📄 Command output / logs

If applicable, paste relevant output here:

```text
(secretscout output or traceback)
```

> Secrets in logs **must be redacted**.

---

## 🖥️ Environment

Please complete the following information:

* OS: (e.g. Windows 11, Ubuntu 22.04, macOS Sonoma)
* Python version:

  ```bash
  python --version
  ```
* SecretScout version:

  ```bash
  secretscout --version
  ```
* Installation method:

  * [ ] Editable install (`pip install -e .`)
  * [ ] PyPI (if applicable)
  * [ ] Other

---

## 🧷 Git / Pre-commit context (if relevant)

* Is this running via **pre-commit**?

  * [ ] Yes
  * [ ] No
* Command used:

  ```bash
  secretscout scan --staged ...
  ```

---

## 📸 Screenshots (optional)

If applicable, add screenshots to help explain the problem.

---

## 🧠 Additional context

Add any other context that might help us understand or reproduce the issue:

* custom rules
* baseline usage
* CI environment
* large repositories
* performance-related notes

---

🙏 Thank you for helping improve **SecretScout**!
