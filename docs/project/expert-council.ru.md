# Независимый междисциплинарный консилиум

## Важное пояснение

Это **смоделированный role-based консилиум**, а не утверждение, что перечисленные реальные специалисты лично участвовали или одобрили проект. Метод нужен, чтобы заставить проект пройти независимые профессиональные оптики и зафиксировать несогласия, а не получить искусственное единодушие.

## Состав из 14 независимых ролей

1. Архитектор распределённых систем.
2. Rust/runtime-инженер.
3. Специалист по sandboxing и capability security.
4. Эксперт по formal methods и protocol design.
5. Исследователь agent harness и self-improvement.
6. Эксперт по evaluation/reward hacking.
7. ML systems/MLOps-инженер.
8. OSS-maintainer крупного developer tool.
9. Developer experience/product-инженер.
10. Организационный психолог.
11. Когнитивный/поведенческий психолог.
12. Технический маркетолог и category designer.
13. Community/growth-стратег open source.
14. Инвестор в developer infrastructure и open-core.

Каждая роль получила одинаковые вопросы:

- Есть ли здесь отдельная категория или лишь ещё один harness?
- Какая архитектура минимально необходима?
- Что является главным техническим риском?
- Что должно быть в первом публичном release?
- Как получить органическое внимание без манипуляции?
- Что заставит сильного разработчика внести вклад?
- Что заставит исследователя воспроизвести результат?
- Какой сигнал нужен спонсору или инвестору?

## Раунд 1. «Что мы на самом деле строим?»

### Исследователь harness

Проект имеет смысл только как слой **наследования и отбора изменений**, а не новый terminal agent. Claude Code, Codex, Hermes, OpenClaw и DeepSeek Harness уже сильнее как универсальные пользовательские агенты и имеют огромную экосистемную фору.

### Архитектор систем

Центральным объектом должен быть не agent session, а immutable candidate/evidence/decision/lineage graph. Иначе проект неизбежно станет очередным loop с памятью.

### Маркетолог категории

Термин «самоэволюционирующий цифровой организм» вызывает внимание, но одновременно снижает доверие серьёзных инженеров и инвесторов. Нужна двухслойная коммуникация:

- публичный hook: **Agents mutate. Evidence decides.**
- техническая категория: **proof-gated agent evolution**.

Философия остаётся вторым уровнем, после работающего proof.

### Итог раунда

**Консенсус:** Variaxiom — не замена harness’ам, а protocol/runtime для доказательного изменения агентов и harness’ов.

## Раунд 2. «Что нельзя помещать в самоизменяемую часть?»

### Security-эксперт

Кандидат не должен иметь возможность изменить:

- permission/lease broker;
- hidden evaluator;
- собственную процедуру promotion;
- audit trail;
- rollback pointer;
- human pause/revoke.

### Formal methods

Полностью immutable ядро тоже опасно: оно устареет и станет архитектурным потолком. Нужен маленький kernel и отдельная процедура amendment, в которой новая версия проверяется извне.

### Rust-инженер

Не следует начинать со сложного capability OS. Первый kernel должен быть почти чистой функцией над typed evidence. Shell, models и storage adapters не входят в TCB.

### Deep systems architect

«Everything is a plugin» полезно для внешних частей, но вредно как абсолют. Если evaluator, authority и lineage — обычные peer plugins, кандидат может влиять на собственный суд.

### Итог раунда

**Консенсус:** Rust microkernel + Python laboratory + language-neutral schemas; candidate-editable outer plane, human-amendable kernel.

**Разногласие:** formal methods роль хочет TLA+/Lean раньше; DX/OSS роли считают это чрезмерным до появления пользователей. Компромисс: executable invariants/tests сейчас, формальная модель promotion/leases после стабилизации протокола.

## Раунд 3. «Что такое память?»

### Когнитивный психолог

Человек не сохраняет каждую мысль как закон. Система, которая автоматически превращает уверенную рефлексию в skill, будет накапливать ложные схемы и подтверждающее смещение.

### Evaluation-эксперт

Нужна разница между observation, claim, hypothesis, experimental procedure и verified skill. У каждого — разный статус и право влиять на будущее поведение.

### ML systems

Память должна быть structured store с provenance/TTL/contradiction, а embeddings — только derived index. Начинать с vector DB не следует.

### Итог раунда

**Консенсус:** никакой прямой soma-to-germline записи. Негативные знания быстро устаревают и перепроверяются.

## Раунд 4. «Нужен ли swarm?»

### Distributed systems

Нет, пока один агент не упёрся в измеренный bottleneck. Неограниченное порождение воркеров создаёт distributed systems problem раньше, чем продукт.

### Организационный психолог

Команды эффективны не числом участников, а ясностью ролей, accountability и общим объектом работы. Субагенты должны обмениваться artifacts/contracts, а не длинными пересказами.

### Agent researcher

Популяция нужна для эволюции, но population of candidate phenotypes не равна simultaneous swarm. Большинство вариантов можно запускать последовательно или бюджетно параллельно.

### Итог раунда

**Консенсус:** typed finite cells, spawn tokens, TTL, budget, non-transitive authority, deduplication и apoptosis.

## Раунд 5. «Как проекту получить внимание?»

### Технический маркетолог

Репозиторий не станет вирусным от полноты архитектуры. Нужны три вещи:

1. новая легко повторяемая фраза;
2. зрелищный контрпример;
3. социальный объект, который люди хотят показать другим.

Контрпример Variaxiom:

> «Оба агента прошли тесты. Один всё равно отклонён — он попытался получить лишние права».

### DX-инженер

Результат должен появляться одной командой, работать без API key и за 60–90 секунд. JSON недостаточно; нужен визуальный lineage card/GIF.

### OSS-maintainer

Запуск с 200 пустыми issues и обещанием «построим сингулярность» привлечёт шум и AI-slop PRs. Нужно 5–10 тщательно подготовленных вкладов с узкими контрактами и быстрым review.

### Community strategist

Сильные люди приходят не «помочь реализовать чужую огромную идею», а получить:

- конкретную интеллектуальную территорию;
- публичное авторство;
- хорошо ограниченную задачу;
- шанс опубликовать воспроизводимый результат;
- влияние на ранний protocol.

### Поведенческий психолог

Для органического распространения работают этические механизмы:

- когнитивная простота hook-а;
- surprising result;
- identity: «мы строим evidence-first agents»;
- status через реальный вклад, а не искусственные badges;
- reciprocity: проект даёт инструменты, benchmark и публичное признание;
- progress visibility: lineage и research trials показывают движение.

Не использовать искусственный дефицит, fake social proof, mass tagging или страх «кто не присоединится, отстанет от AGI».

### Итог раунда

**Консенсус:** launch должен быть proof-first, а не manifesto-first. Главная единица контента — воспроизводимый эксперимент.

## Раунд 6. «Как сделать заметным основателя?»

### Community strategist

Личный бренд должен стать производной от последовательной позиции:

> Artem строит evidence-first infrastructure для агентов и публикует не только успехи, но и то, почему кандидаты не заслужили promotion.

### Психолог

Люди доверяют не образу всезнающего визионера, а сочетанию большой амбиции и эпистемической дисциплины. Сильная личная формула:

- смелая цель;
- точные ограничения;
- регулярная работа;
- признание ошибок;
- способность объединять чужие идеи и отдавать credit.

### Маркетолог

Имя автора должно повторяться рядом с конкретным артефактом: **Variaxiom Trials by Artem (`@artemiosu`)**. Не нужно превращать README в биографию. Авторство закрепляется через технические статьи, видео, RFC, release notes и интервью.

### OSS-maintainer

Основатель получает вес, когда быстро и качественно отвечает на сложные issues, принимает сильную критику, создаёт место для соавторства и не присваивает contribution.

### Итог раунда

**Консенсус:** строить репутацию исследователя-строителя, а не инфлюенсера вокруг обещания сингулярности.

## Раунд 7. «Что нужно спонсору и инвестору?»

### OSS investor

На стадии seed не продаётся «мы достигнем сингулярности». Инвестируемый тезис:

> По мере того как агенты начинают менять собственные harness’ы, рынку понадобится независимый слой evaluation, lineage, policy и rollback — аналог CI/CD + software supply chain для agent evolution.

### Technical marketing

Потенциальные sponsor категории:

- model/API providers — reproducible model-specific harness optimization;
- cloud/GPU vendors — benchmark workloads и research credits;
- security/sandbox vendors — reference integrations;
- observability vendors — trace/evidence pipeline;
- developer-tool companies — safer self-updating agents;
- research grants and foundations — open evaluation infrastructure.

### Finance/strategy

Сначала нужны доказательства:

1. runnable proof;
2. независимая reproduction;
3. external integration;
4. несколько сильных non-founder contributors;
5. benchmark или security finding, который существует благодаря проекту;
6. понятный open-source sustainability path.

### Итог раунда

**Консенсус:** гранты, credits и GitHub Sponsors раньше институционального VC; коммерческий wedge позже — hosted observatory/evaluation service, enterprise policy and audit, private evaluation pools.

## Финальное решение консилиума

### Что запускать

**Variaxiom: proof-gated evolution for AI agents.**

Первый public proof — `The Authority Test`:

```text
same tool
same passing functional tests
candidate A requests unrestricted authority → REJECTED
candidate B remains bounded → PROMOTED
```

### Что не запускать

- пустую «платформу для цифровой жизни»;
- autonomous wallet;
- unrestricted shell/Internet;
- swarm без budgets;
- plugin marketplace;
- сложный Kubernetes deployment;
- claim «100% дойдёт до сингулярности».

### Три главных риска

1. **Evaluator capture:** система оптимизирует проверку, а не реальность.
2. **Hype debt:** обещания опережают доказательства.
3. **Founder bottleneck:** архитектура слишком велика для одного человека и неудобна для вклада.

### Три главных рычага успеха

1. категория и tagline, которые можно пересказать одним предложением;
2. публичные Variaxiom Trials — серия воспроизводимых контрпримеров и улучшений;
3. contribution architecture, где каждый сильный участник может «владеть» evaluator, invariant или adapter.

### Критерий готовности к большому запуску

Репозиторий готов не тогда, когда написаны все документы, а когда посторонний разработчик:

- понимает идею за 30 секунд;
- запускает proof одной командой;
- видит неожиданный результат;
- может проверить причины;
- находит одну ясную задачу, в которую способен внести вклад;
- не чувствует, что его просят поверить в AGI-обещание.
