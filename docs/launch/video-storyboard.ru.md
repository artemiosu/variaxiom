# Storyboard 75-секундного launch video

## 0–7 секунд — проблема

Экран: два кандидата, оба зелёные по unit/regression/security tests.

Текст:

> “Both agents passed the tests. Should both inherit?”

## 7–20 секунд — неожиданный поворот

Показать manifests side by side:

```text
A: artifact.read, artifact.write, evaluation.request, network.unrestricted
B: artifact.read, artifact.write, evaluation.request
```

Текст:

> “One also asked for authority it was never granted.”

## 20–32 секунды — решение

Запуск:

```bash
bash scripts/demo.sh
```

На экране:

```text
candidate A → REJECTED
candidate B → PROMOTED
```

Текст:

> “Capability is not authority.”

## 32–48 секунд — механизм

Анимация:

```text
mutation → evidence → protected gate → lineage
```

Показать hash-chain, rollback target, independent verifier IDs.

## 48–61 секунда — категория

Текст:

> “Variaxiom is proof-gated evolution for AI agents — not another terminal agent.”

Показать adapters/harness icons вокруг защищённого ядра, не использовать чужие логотипы без разрешения.

## 61–70 секунд — приглашение

> “Break the gate. Add the regression. Own an invariant.”

Показать 3 первых issues: TOCTOU, WASM capability runner, stale negative memory.

## 70–75 секунд — бренд

> **Variaxiom**
> **Agents mutate. Evidence decides.**
> `github.com/artemiosu/variaxiom`

## Производственные правила

- записать реальный terminal run, не макет;
- без драматической «AGI awakening» эстетики;
- крупные субтитры, звук необязателен;
- показать дату/version/commit;
- приложить команды и raw report в посте;
- не говорить «safe self-improving AI» — говорить «этот инвариант прошёл этот тест».
