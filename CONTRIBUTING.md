# Contributing

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

## Добавление нового правила
1) Добавь Rule в `src/secretscout/rules.py`
2) Добавь тест в `tests/`
3) Обнови `docs/RULES.md`
