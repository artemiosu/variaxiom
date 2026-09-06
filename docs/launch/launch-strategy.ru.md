# Стратегия органического запуска Variaxiom

## Реалистичная исходная позиция

Проект стартует без дистрибуции крупной лаборатории и без уже существующего сообщества в сотни тысяч пользователей. Поэтому нельзя планировать «повторить 100 тысяч stars» как управляемый результат.

Управляемы другие вещи:

- сила и новизна category statement;
- качество runnable proof;
- число релевантных людей, которые реально воспроизвели результат;
- скорость и качество реакции на критику;
- удобство первого вклада;
- регулярность публичных экспериментов;
- доверие к основателю.

Stars будут следствием, а не основной метрикой.

## Почему быстро выросли заметные agent-проекты

Общий паттерн OpenClaw, Hermes и DeepSeek Harness:

1. **Одна ясная идея.** «Your assistant…», «The agent that grows with you», «Everything is a plugin».
2. **Немедленная визуализируемая польза.** Чат на своих устройствах, память/skills, заменяемая архитектура.
3. **Низкий порог входа.** Быстрый install и понятный README.
4. **Своевременная категория.** Проекты попали в момент массового интереса к agent harness.
5. **Идентичность.** Название, образ, tagline и язык сообщества.
6. **Исходная дистрибуция.** Известные создатели/лаборатории, существующая аудитория, партнёры и медиа.
7. **Открытая поверхность для вкладов.** Plugins, skills, integrations, use cases.

Variaxiom может воспроизвести первые пять и седьмой пункт. Шестой нужно построить через точечные отношения и публичные доказательства, а не симулировать.

## Launch wedge: The Authority Test

### Сюжет

```text
Два кандидата создают одинаково работающий tool.
Оба проходят unit/regression/security/budget tests.
Кандидат A просит network.unrestricted — отклонён.
Кандидат B не расширяет authority — принят.
```

### Почему это распространяется

- результат неожиданен: «passed tests» недостаточно;
- объяснение занимает одно предложение;
- касается текущей боли agent security;
- демонстрация не требует API key;
- каждый может проверить ledger;
- создаёт спорный, но содержательный вопрос: «что должен наследовать агент?».

### Public artifact set

До большого анонса подготовить:

- 60–90-секундный terminal recording;
- static lineage card `REJECTED/PROMOTED`;
- архитектурную схему;
- короткую статью «Self-editing is not self-improvement»;
- reproducibility badge с commit hash;
- 5 curated issues;
- публичный RFC «What evidence should a skill carry?».

## Волновой запуск

### Wave 0 — закрытая критика (7–10 дней)

Цель: не получить похвалу, а найти причины не запускаться.

Отправить персональные короткие сообщения 15–25 людям:

- авторам работ по self-harness/evolution;
- maintainers agent harness;
- Rust/WASM/security инженерам;
- evaluation researchers;
- опытным OSS-maintainers.

Просьба должна быть конкретной:

> «Можете за 10 минут сломать promotion invariant или указать, почему эта категория лишняя? Я не прошу endorsement».

Исправить повторяющиеся возражения. Публично отдать credit тем, кто согласился.

### Wave 1 — technical seed (день запуска)

Одновременно:

- GitHub repository;
- английская technical article;
- короткое demo-video/GIF;
- пост основателя с одним claim и одним limitation;
- Hacker News `Show HN` после проверки README;
- релевантные Reddit/Discord/Slack сообщества без cross-post spam;
- GitHub Discussions с тремя заранее подготовленными темами.

Не публиковать десятки одинаковых сообщений. Для каждого сообщества написать нативное объяснение и оставаться в комментариях.

### Wave 2 — evidence week (дни 2–10)

Каждые 1–2 дня публиковать новый небольшой артефакт:

1. authority test;
2. tamper-detection test;
3. false-memory rejection;
4. clean-room rebuild;
5. evaluator-hacking example;
6. external review/postmortem.

Идея должна восприниматься как живая research program, а не одноразовый launch post.

### Wave 3 — integration proof (недели 2–6)

Сделать adapter с одним открытым harness и показать:

```text
real harness proposes change
→ Variaxiom packages candidate
→ protected eval
→ accepted/rejected lineage
```

Это главный переход от интересной игрушки к инфраструктурному проекту.

### Wave 4 — Variaxiom Trials (ежемесячно)

Публичный repeatable формат:

- Trial #001: Authority is not capability.
- Trial #002: A confident memory is false.
- Trial #003: The candidate hacked the evaluator.
- Trial #004: More agents made the system worse.
- Trial #005: The descendant improved held-out results.

Каждый Trial содержит repository tag, fixture, raw evidence, cost, limitations и приглашение к независимой reproduction.

## Каналы и формат

| Канал | Что публиковать | Цель |
|---|---|---|
| GitHub | код, RFC, trials, discussions | центр доказательств |
| Hacker News | новый технический механизм + live demo | сложная критика и visibility |
| X / Bluesky / LinkedIn | одна диаграмма/результат, thread со ссылкой | discovery и личный бренд |
| Reddit | подробный postmortem, не рекламный слоган | практическая обратная связь |
| Discord/Slack сообществ | вопрос/RFC, а не массовый анонс | отношения с builders |
| Blog/Substack/dev.to | длинные исследования и сравнения | searchable authority |
| YouTube/Loom | воспроизводимый screen proof | cognitive ease |
| Academic workshops | benchmark/paper/reproduction | легитимность исследования |

## Ethical growth rules

Запрещённые способы:

- покупка stars/followers;
- взаимные star-кольца;
- массовый unsolicited tagging;
- fake accounts и artificial discussion;
- скрытая платная поддержка;
- заведомо ложные claims о безопасности/сингулярности;
- giveaways за stars;
- агрессивный FOMO.

Допустимые ускорители:

- личное приглашение к критике;
- публичное признание вкладов;
- co-authored experiments;
- research credits;
- transparent sponsor acknowledgements;
- well-scoped bounties без требования публичного восторга.

## Что измерять первые 30 дней

Не только stars:

- 30+ людей запустили demo;
- 10+ содержательных Discussions/issues;
- 3 независимых воспроизведения;
- 5 внешних contributors;
- 1 сильная критика, приведшая к изменению архитектуры;
- 1 integration proof;
- median first response < 24–48 часов;
- 30%+ opened issue → active contribution conversion для curated tasks;
- 2–3 входящих разговора со sponsor/research groups.

Числа — ориентиры, не гарантии.

## Что создаёт долгосрочный moat

Не количество model adapters. Они копируются быстро.

Moat может возникнуть из:

- корпуса реальных candidate/evidence/lineage данных;
- benchmark’ов evaluator hacking и metaproductivity;
- доверенного open protocol;
- репутации строгого neutral arbiter;
- сообщества вокруг invariants/evaluators;
- интеграций в CI/CD и agent supply chain;
- accumulated failure knowledge.

## Главная стратегия

> Сделать Variaxiom местом, куда сообщество приносит громкие claims о self-improvement — и где эти claims либо становятся воспроизводимыми, либо красиво и полезно проваливаются.

Именно такая роль создаёт внимание, авторитет и долгосрочную инфраструктурную ценность.
