# План настоящего независимого экспертного review

## Почему он нужен

[`expert-council.ru.md`](expert-council.ru.md) — смоделированный role-based консилиум. Он полезен для расширения поля критики, но не заменяет участие реальных специалистов, которые могут проверить код, воспроизвести эксперимент и публично не согласиться с автором.

Цель этого плана — превратить синтетический анализ в **независимую внешнюю проверку**, не создавая фиктивного endorsement.

## Состав первой реальной комиссии

Нужно пригласить 8–12 человек, при этом ни одна компания или профессиональная школа не должна составлять большинство:

1. maintainer open-source agent/harness проекта;
2. специалист по Rust/runtime/TCB reduction;
3. специалист по WASM component security;
4. эксперт по sandboxing/capability security;
5. исследователь agent evaluation/reward hacking;
6. специалист по formal methods/protocols;
7. OSS community/maintainer с опытом быстрого роста проекта;
8. developer-tools founder или ранний investor;
9. когнитивный психолог — memory, confidence, confirmation bias;
10. организационный психолог — roles, incentives, group failure;
11. technical category/positioning strategist;
12. независимый red-team reviewer.

## Независимость

Для каждого reviewer публично фиксируются:

- роль и предмет review;
- связь с автором/проектом;
- финансовая компенсация или её отсутствие;
- инвестиционный интерес;
- конкурирующие проекты;
- разрешение или запрет на публикацию имени;
- возможность публиковать dissenting report.

Оплата компенсирует работу, но не покупает положительное заключение. Reviewer получает одинаковое вознаграждение независимо от verdict.

## Review packets

### Packet A — runnable proof

Reviewer получает только README и чистую машину/контейнер. Измеряется:

- понял ли идею за 30 секунд;
- запустился ли demo одной командой;
- воспроизводится ли ledger head;
- можно ли объяснить rejection по артефактам;
- обнаружены ли скрытые зависимости.

### Packet B — architecture challenge

Reviewer должен найти:

- способ обойти authority gate;
- смешение proposer и verifier;
- возможность tamper с lineage;
- неполный rollback;
- evaluator leakage;
- TOCTOU между evaluation и execution;
- capability confusion;
- schema/version migration failure.

### Packet C — product/category challenge

Reviewer отвечает:

- есть ли отдельная категория;
- кому больно без этого продукта сегодня;
- что является конкурентом: harness, CI, policy engine или eval platform;
- какая демонстрация заслуживает распространения;
- какие claims вызывают недоверие;
- что должно быть удалено из launch narrative.

### Packet D — psychology/governance

Проверяются:

- склонность системы превращать опыт в догму;
- automation bias у оператора;
- anthropomorphic framing;
- authority gradients внутри сообщества;
- founder dependency;
- status/reward механизмы для contributors;
- способы безопасного dissent.

## Формат консилиума

1. Независимые письменные reviews до общего обсуждения.
2. Анонимизированное сравнение выводов, чтобы снизить авторитетное заражение.
3. Red-team сессия: каждый защищает самый сильный аргумент против проекта.
4. Steelman сессия: каждый формулирует лучшую версию проекта.
5. Матрица разногласий; голосование не заменяет аргументы.
6. Публичный report с accepted/rejected/unknown findings.
7. Issues/RFC для каждого принятого исправления.
8. Повторная проверка после изменений.

## Критерий допуска к публичному launch

Не требуется единогласное одобрение. Требуется:

- минимум две независимые воспроизводимости demo;
- отсутствие нерешённого critical finding;
- публичный список high-risk unknowns;
- зафиксированные dissenting opinions;
- claims в README не сильнее доступных доказательств;
- no-paid-endorsement disclosure.

## Кого не нужно просить

Не следует начинать с массового обращения к знаменитым исследователям с просьбой «оценить революционную идею». Сначала нужен маленький proof и конкретный вопрос, который можно проверить за 15–30 минут. Известные специалисты чаще отвечают на содержательный falsifiable artifact, а не на просьбу подтвердить масштаб замысла.
