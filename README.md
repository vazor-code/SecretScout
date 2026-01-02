# SecretScout 🕵️‍♂️🔐 (defensive)

**SecretScout** — defensive CLI-сканер, который помогает **не закоммитить секреты**
(токены/ключи/пароли) в репозиторий.

- ✅ Красивый отчёт в терминале (Rich)
- ✅ Форматы: **table / minimal / json / sarif / html**
- ✅ `init` / `fix` — генерирует `.secretscout.toml`, `.secretscoutignore`, `.pre-commit-config.yaml`
- ✅ `--staged` — проверка **staged** файлов (как pre-commit)
- ✅ **baseline** — “запомнить старые проблемы” и фейлить только новые
- ✅ Быстро: кэш + параллельное сканирование

> Цель: **защитить свои проекты**. Не использовать во вред.

---

## Установка (dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

---

## Быстрый старт

```bash
# 1) создать конфиги и pre-commit (не ломает существующие файлы)
secretscout init .

# 2) быстрый скан git-tracked файлов
secretscout scan .

# 3) скан staged (для pre-commit)
secretscout scan --staged --format minimal --fail-on high

# 4) JSON для CI
secretscout scan . --format json

# 5) SARIF для GitHub Code Scanning
secretscout scan . --format sarif --output secretscout.sarif

# 6) HTML отчёт
secretscout scan . --format html --output secretscout_report.html
```

---

## Команды

### `scan`
Сканирует:
- по умолчанию: **git tracked** (если это git-репо)
- `--all` : все файлы в папке
- `--staged` : staged файлы из git index

Флаги:
- `--format table|minimal|json|sarif|html`
- `--output <file>` (иначе в stdout)
- `--fail-on low|medium|high|critical`
- `--baseline .secretscout.baseline.json`
- `--no-cache` (по умолчанию кэш включён)
- `--max-findings 200`
- `--exclude "path/**"` (добавить исключения на лету)

### `init` / `fix`
Создаёт/обновляет:
- `.secretscout.toml` (конфиг)
- `.secretscoutignore` (паттерны исключений)
- `.pre-commit-config.yaml` (локальный hook)
- секцию в `.gitignore`

### `baseline`
```bash
secretscout baseline .                 # создаст .secretscout.baseline.json
secretscout scan . --baseline .secretscout.baseline.json
```

### `rules`
```bash
secretscout rules list
secretscout rules show github-token
```

### `stats`
```bash
secretscout stats .        # сводка по severity/rule/file
```

---

## Игнорирование

1) `.secretscoutignore` — glob-паттерны (строка = паттерн, `#` = комментарий)
2) Inline:
- `secretscout:ignore` — игнорирует строку
- `secretscout:ignore-file` — если встречается в первых 5 строках файла, игнорирует файл

---

## Exit codes

- `0` — нет проблем (выше порога fail_on)
- `1` — найдено (>= fail_on)
- `2` — runtime error
