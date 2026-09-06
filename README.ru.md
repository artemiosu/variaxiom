# Variaxiom

<p align="center"><img src="assets/variaxiom-wordmark.svg" alt="Variaxiom — Agents mutate. Evidence decides." width="820"></p>

**Агенты мутируют. Доказательства решают.**

Variaxiom — открытая доказательно управляемая эволюционная среда для ИИ-агентов. Проект исследует вопрос, который обычные agent harness решают недостаточно строго:

> Как позволить агенту менять свои skills, tools, workflows, память и затем собственный harness, **не выдавая любое самоизменение за самоулучшение**?

Современная модель уже способна предложить новый код. Мутация сравнительно проста. Трудная часть — наследование: какое изменение действительно полезно, безопасно, воспроизводимо и заслуживает войти в устройство следующих поколений агентов.

Variaxiom делает это решение явным, проверяемым и аудируемым.

[English](README.md) · [Архитектура](docs/architecture/overview.md) · [Дорожная карта](docs/project/roadmap.md) · [Стратегия запуска](docs/launch/launch-strategy.ru.md)

> **Статус:** pre-alpha research seed. В репозитории уже есть исполняемый вертикальный срез, схемы контрактов, каркас доверенного Rust-ядра и полный проектный пакет. Это пока не production-платформа автономии.

## Идея за одну минуту

Рабочий агент может предложить мутацию, но не может самостоятельно сделать её наследуемой.

```text
рабочий агент (сома)
        │ предлагает
        ▼
кандидат: skill / tool / изменение harness
        │
        ├── целостность и lineage
        ├── независимые evaluators
        ├── regression/adversarial tests
        ├── бюджет и полномочия
        └── доказанный rollback
        │
        ▼
конституционный promotion gate
        │
        ├── rejected → остаётся свидетельством
        └── accepted → входит в наследуемый геном
```

Variaxiom разделяет четыре процесса, которые часто смешиваются:

1. **Генерация:** модели создают варианты.
2. **Оценка:** независимые системы измеряют последствия.
3. **Отбор:** детерминированная политика решает судьбу кандидата.
4. **Полномочия:** доступ к внешнему миру управляется отдельно.

Более умный кандидат не получает больше прав автоматически.

## Чем Variaxiom отличается

| Обычный harness | Variaxiom |
|---|---|
| Один агент переписывает себя | Популяция временных фенотипов предлагает варианты |
| Память — растущий набор заметок | У утверждений есть происхождение, область, уверенность, срок и условия опровержения |
| Новый skill — текстовая инструкция | Наследуемый skill — версионированный пакет с тестами и evidence |
| Один агент может быть автором и судьёй | Автор, verifier, selector и deployer разделены |
| Улучшился benchmark — значит обновляем | Нужен многомерный evidence envelope без нарушения hard constraints |
| Способность часто смешивается с доступом | Capability и authority ортогональны |
| Текущая версия перезаписывается | Сохраняются content-addressed lineage и rollback target |
| «Self-improving» — рекламное обещание | Улучшение — проверяемое отношение между поколениями |

## Запуск демонстрации

Bootstrap-реализация не имеет runtime-зависимостей кроме Python 3.13+.

```bash
git clone https://github.com/artemiosu/variaxiom.git
cd variaxiom
bash scripts/demo.sh
```

Демонстрация дважды оценивает один функциональный tool package:

- кандидат с `network.unrestricted` отклоняется, хотя функциональные тесты прошли;
- кандидат без расширения authority принимается после независимых проверок.

Проверить lineage:

```bash
PYTHONPATH=src python3 -m variaxiom --home .variaxiom status
PYTHONPATH=src python3 -m variaxiom --home .variaxiom verify
cat .variaxiom/reports/demo-report.json
open .variaxiom/reports/authority-test.html  # macOS; use your browser elsewhere
cat .variaxiom/lineage.ledger.jsonl
```

[Открыть сохранённый отчёт Authority Test](docs/demo/authority-test.html)

Полная локальная проверка:

```bash
bash scripts/verify.sh
```

## Архитектура

```text
 Человек / внешний governance
              │
   подписанная constitution и grants
              │
    ┌─────────▼──────────┐
    │ Доверенный kernel  │
    │ promotion · lineage│
    │ budgets · rollback │
    │ capability leases  │
    └─────────┬──────────┘
              │
    ┌─────────▼──────────┐
    │ Evolution lab      │
    │ variants · archive │
    │ evals · adversaries│
    └─────────┬──────────┘
              │ собирает
    ┌─────────▼──────────┐
    │ Временный phenotype│
    │ models · memory    │
    │ skills · tools     │
    │ task-local agents  │
    └─────────┬──────────┘
              │ outcomes
              └────────────► внешняя реальность
```

Целевая система двухскоростная:

- небольшое **Rust-ядро** для security-sensitive инвариантов;
- **Python research plane** для моделей, evaluators и быстрого экспериментирования;
- **WebAssembly Component Model/WIT** как основной переносимый контракт для создаваемых агентом tools;
- OCI/gVisor/Firecracker-класс изоляции для нагрузок, которые не помещаются в WASM capability envelope.

Первый релиз остаётся модульным монолитом. Kafka, Kubernetes, распределённая vector DB и автономная покупка облачных ресурсов сознательно не входят в MVP.

## Конституционные инварианты

Bootstrap-конституция находится в [`constitution/`](constitution/):

- **Capability не равна authority.** Рост интеллекта не расширяет permissions.
- **Нет прямой записи soma → germline.** Рабочий агент предлагает, внешний gate наследует.
- **Реальность важнее self-report.** Уверенность модели не является доказательством.
- **Evaluators защищены.** Кандидат не видит hidden tests и не переписывает своего судью.
- **Каждый потомок ограничен.** Нужны parent, mission, budget, lease, TTL и termination condition.
- **Нет терминальной цели самосохранения.** Service continuity допустима только в рамках заданной политики.
- **Нет автономной финансовой власти.** Расходование ресурсов делегируется явно и отзываемо.
- **Rollback переживает promotion.** Последняя жизнеспособная версия сохраняется.

## Что проект должен доказать

Variaxiom строится вокруг фальсифицируемых стадий, а не обещания неизбежной «сингулярности»:

1. воспроизводимые изменения агента;
2. безопасное создание tools и skills;
3. наследование улучшений в clean-room поколениях;
4. открытый архив без diversity collapse;
5. улучшение самого механизма улучшения;
6. снижение человеческого микроменеджмента без authority drift;
7. положительная внешняя ценность после полного учёта compute, координации и риска.

Самая амбициозная цель — **измеримое рекурсивное улучшение**: поколение становится лучше не только в решении задач, но и в создании независимо проверенных потомков. Нельзя честно гарантировать бесконечный рост; можно построить инвариант, при котором непроверенное изменение не попадает в доверенную lineage.

## Карта репозитория

```text
constitution/       Машиночитаемые инварианты
crates/             Rust protocol, kernel и CLI scaffold
src/variaxiom/      Исполняемая Python reference laboratory
schemas/            Контракты candidate/evidence/skill/tool
wit/                Интерфейс WebAssembly components
examples/           Минимальные демонстрации

docs/architecture/ Архитектура, безопасность, память и ADR
docs/research/     Анализ существующих систем и research agenda
docs/project/      Charter, roadmap, metrics, risks, expert council
docs/launch/       Positioning, community, founder и sponsor strategy
```

## Как внести вклад

Самые важные ранние вклады — не очередной model provider, а:

- формально определённый promotion invariant;
- воспроизводимый adversarial evaluator;
- content-addressed формат skill/tool package;
- capability-bounded WASM runner;
- эксперимент, обнаруживающий пропущенную регрессию;
- benchmark эволюционной продуктивности, а не только one-shot score.

Начните с [`CONTRIBUTING.md`](CONTRIBUTING.md), [roadmap](docs/project/roadmap.md) и issues с метками `good first issue`, `invariant`, `evaluator`, `research replication`.

## Ответственные границы

Variaxiom предназначен для ограниченных исследований и управляемой автоматизации. Проект не развивает скрытность, неконтролируемое размножение, сохранение против воли оператора, добычу credentials, автономное финансовое выживание или обход ограничений платформ. См. [`SECURITY.md`](SECURITY.md) и [threat model](docs/architecture/threat-model.md).

## Название

**Variaxiom = variation + axiom:** изменяться может почти всё, но наследование ограничено явными инвариантами.

Код распространяется по Apache-2.0. Правила использования имени описаны в [`TRADEMARKS.md`](TRADEMARKS.md).

---

**Variaxiom — Агенты мутируют. Доказательства решают.**
