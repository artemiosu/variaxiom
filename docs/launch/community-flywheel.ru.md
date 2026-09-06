# Community Flywheel

## Принцип

Сообщество растёт, когда вклад создаёт участнику собственный капитал: знание, авторство, репутацию, влияние и полезный инструмент.

```text
понятный proof
→ человек воспроизводит
→ находит пробел
→ получает узкую область владения
→ создаёт evaluator/invariant/adapter
→ публично признан соавтором
→ приводит новых reproducer/contributors
→ корпус доказательств становится ценнее
```

## Contribution ladder

### Уровень 1 — Observer

Запускает demo, читает Trial, голосует/комментирует RFC.

### Уровень 2 — Reproducer

Публикует environment + commit + outcome. Получает запись в `REPRODUCERS.md`.

### Уровень 3 — Breaker

Находит counterexample, evaluator exploit или missing invariant. Это престижный вклад, а не «негатив».

### Уровень 4 — Builder

Добавляет evaluator, tool package, adapter, visualization или protocol implementation.

### Уровень 5 — Steward

Поддерживает область, reviews evidence, ведёт Trial/RFC.

### Уровень 6 — Constitutional reviewer

Получает ограниченную роль после длительного доверия и независимого judgment.

## Программы

### Adopt an invariant

Участник выбирает `VX-INV-*`, создаёт спецификацию, adversarial tests и implementation matrix. Его имя закрепляется за результатом.

### Variaxiom Breakers

Ежемесячный challenge: сломать evaluator или promotion rule в безопасном fixture. Победитель получает публичный write-up, credit и при наличии funding — bounty.

### Harness Bridges

Maintainers внешних harness’ов совместно создают adapter и сохраняют контроль над своей интеграцией.

### Reproduction grants

Небольшие credits/bounties независимым людям, которые воспроизводят Trial на другой ОС, модели или harness.

### Research working groups

- Evidence & Evals;
- Capability Security;
- Memory & Knowledge;
- Evolution & Diversity;
- Runtime/WASM;
- Developer Experience.

## Community protections

- issue claiming и expiry, чтобы избежать дублирования;
- PR evidence template;
- лимиты на одновременно открытые крупные PR одного автора при перегрузке;
- запрет low-effort AI-generated bulk PRs;
- обязательный human-readable rationale;
- contributor credit в release notes;
- решения через public RFC, а не закрытый чат;
- Code of Conduct и private reporting.

## Recognition

Признание привязано к проверяемому вкладу:

- `Reproduced by`;
- `Invariant steward`;
- `Evaluator author`;
- `Counterexample discovered by`;
- co-authorship в Trial/report/paper;
- release notes и website contributors.

Не использовать meaningless gamification и token economics на раннем этапе.
