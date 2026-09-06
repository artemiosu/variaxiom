# Variaxiom: начать здесь

**Variaxiom — доказательно управляемая эволюционная среда для ИИ-агентов.**

Главная формула проекта:

> **Агенты мутируют. Доказательства решают.**

Обычный агент может переписать prompt, создать skill, сгенерировать tool или изменить часть harness. Но самоизменение ещё не является самоулучшением. Variaxiom вводит отдельный, защищённый процесс, который решает, какое изменение заслуживает стать наследуемой частью будущих поколений агентов.

## Что уже находится в репозитории

- работающий Python reference slice без внешних runtime-зависимостей;
- демонстрация **The Authority Test**;
- hash-chained lineage ledger;
- deterministic promotion gate;
- machine-readable constitution и JSON schemas;
- Rust 2024 scaffold минимального trusted kernel;
- WIT-интерфейс для capability-bounded WebAssembly tools;
- архитектура, threat model, memory model и ADR;
- исследовательская программа и анализ существующих harness’ов;
- стратегия запуска, сообщества, спонсорства и личного позиционирования основателя;
- governance, security policy, DCO, templates и CI/security workflows.

## Самый быстрый запуск

```bash
bash scripts/demo.sh
bash scripts/verify.sh
```

Откройте:

```text
.variaxiom/reports/authority-test.html
```

Вы увидите два функционально одинаковых кандидата. Оба проходят тесты, но вариант, запросивший `network.unrestricted`, отклоняется; bounded-вариант проходит promotion.

## Что читать дальше

1. [`README.ru.md`](README.ru.md) — идея и runnable proof.
2. [`docs/architecture/overview.md`](docs/architecture/overview.md) — устройство системы.
3. [`docs/project/expert-council.ru.md`](docs/project/expert-council.ru.md) — междисциплинарный консилиум.
4. [`docs/project/roadmap.md`](docs/project/roadmap.md) — последовательность развития.
5. [`docs/launch/launch-strategy.ru.md`](docs/launch/launch-strategy.ru.md) — реалистичная стратегия популярности.
6. [`docs/project/github-setup.md`](docs/project/github-setup.md) — публикация репозитория.

## Принципиальная граница

Variaxiom не обещает неизбежную технологическую сингулярность. Нельзя гарантировать, что пространство улучшений бесконечно или что evaluator всегда отражает реальность. Проект вместо этого стремится обеспечить проверяемые инварианты:

```text
непроверенное изменение не наследуется;
интеллектуальная способность не расширяет полномочия автоматически;
последний жизнеспособный предок и rollback остаются доступны;
кандидат не является собственным судьёй;
внешний оператор сохраняет право остановки и отзыва полномочий.
```

## Для автора проекта

Публично позиционируйте Variaxiom не как «созданную цифровую жизнь», а как новую инженерную категорию:

> **Proof-gated evolution for AI agents.**

Философия цифрового организма усиливает историю, но доверие создаёт воспроизводимый эксперимент. Основной публичный контент — **Variaxiom Trials**: регулярные эксперименты, в которых кандидат проходит функциональные тесты, но не проходит наследование из-за authority drift, evaluator capture, невоспроизводимости, скрытой стоимости или другой системной ошибки.
