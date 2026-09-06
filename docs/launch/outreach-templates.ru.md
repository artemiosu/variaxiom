# Персонализированный outreach: шаблоны и правила

## Главное правило

Не просить: «Посмотрите мой революционный проект и помогите сделать его популярным».

Просить: «Мы построили воспроизводимый counterexample к конкретному failure mode. Вы работали над близкой проблемой; вот один проверяемый вопрос, на который ваш опыт особенно релевантен».

Каждое сообщение должно содержать:

- почему выбран именно этот человек;
- один артефакт, а не весь репозиторий;
- один ограниченный вопрос;
- честный срок проверки артефакта, без требования звонка;
- отсутствие просьбы публично поддержать проект;
- право проигнорировать сообщение без повторного давления.

## Maintainer agent harness

```text
Тема: reproducible authority-drift test for self-changing agents

Здравствуйте, [имя]. В Variaxiom мы отделяем создание изменения агентом от права сделать это изменение наследуемым. В первом proof два функционально одинаковых tool-кандидата проходят тесты, но вариант с новой невыданной authority отклоняется детерминированным gate.

Ваш опыт с [конкретный механизм проекта человека] делает особенно ценным один вопрос: где проходит минимальная граница между изменяемым harness и защищённым promotion/evaluation plane?

Proof запускается одной командой и не требует API key: [ссылка на конкретный demo]. Мне полезнее критический counterexample, чем endorsement. Полный контекст не нужен; достаточно посмотреть decision artifact и назвать самый очевидный обход.
```

## Security / sandbox expert

```text
Мы проверяем не “безопасен ли AI вообще”, а более узкий инвариант: кандидат не должен расширять authority вследствие более высокого task score. Вот manifest, evidence и promotion decision одного эксперимента.

Какой первый TOCTOU/confused-deputy/capability-laundering attack вы бы попытались провести? Я превращу ответ в публичный regression test и укажу авторство finding.
```

## Researcher / evaluator expert

```text
Variaxiom пытается измерять не только performance агента, но и metaproductivity — способность порождать более сильных, независимо проверенных потомков. У нас пока нет хорошего metric.

Вот короткая постановка и два counterexample. Какой эксперимент мог бы фальсифицировать предложенную метрику? Положительное мнение не требуется; нужен лучший способ сломать её.
```

## Potential contributor

```text
У проекта есть узкая задача [issue], где результатом будет [конкретный artifact/test]. Она не требует принять всю философию Variaxiom. Вы получите ownership RFC/компонента и явное авторство в release notes.

Перед началом я готов ответить только на архитектурные ограничения; реализация и dissent остаются вашими. Вот acceptance criteria и non-goals: [issue].
```

## Sponsor / infrastructure provider

```text
Variaxiom — open research infrastructure для proof-gated agent evolution. Мы не просим финансировать обещание AGI. Нужен ограниченный ресурс для публичного benchmark: [N] воспроизводимых sandboxed runs с опубликованной полной стоимостью и отрицательными результатами.

Спонсор не влияет на evaluator/verdict и получает disclosure, benchmark report и integration credit — не гарантированное положительное заключение.
```

## Investor after traction

```text
Агенты начинают менять tools, memory policies и harness code, но индустрии не хватает независимого слоя lineage, evaluation, policy и rollback. Variaxiom строит этот слой как open protocol/runtime.

Проверяемые сигналы сегодня: [independent reproductions], [external adapters], [non-founder contributors], [Trials], [usage]. Коммерческий wedge — hosted observatory/private eval pools/enterprise policy and audit, при сохранении открытого protocol core.
```

## Запрещённые приёмы

- массовые одинаковые DM;
- тегирование известных людей ради охватов;
- fake stars, paid stars, взаимные star rings;
- заявления об endorsement без явного разрешения;
- ложный дефицит и страх «кто не войдёт сейчас, проиграет AGI»;
- публикация приватной критики без согласия;
- сокрытие оплаты reviewer или sponsor influence.
