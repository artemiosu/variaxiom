# Первые публичные issues

Не создавать десятки общих задач. Ниже — десять ограниченных вкладов, которые одновременно улучшают продукт и позволяют сильному участнику получить видимое авторство.

## 1. Formalize `no-authority-drift` as an executable invariant

**Labels:** `invariant`, `good first research issue`, `kernel`  
**Outcome:** таблица переходов baseline/requested/granted capabilities + property tests.  
**Non-goal:** полный policy language.  
**Evidence:** тесты должны находить минимум три класса escalation.

## 2. Implement a capability-bounded WASM “hello tool”

**Labels:** `wasm`, `rust`, `tool-runtime`  
**Outcome:** компонент читает вход и возвращает output без filesystem/network authority.  
**Evidence:** denial tests на невыданные imports.

## 3. Detect verifier–proposer collusion

**Labels:** `evaluator`, `security`, `research`  
**Outcome:** расширить evidence envelope так, чтобы один principal не мог скрыться за двумя строковыми идентификаторами.  
**Evidence:** adversarial fixture и documented trust assumptions.

## 4. Define the first public Variaxiom Trial format

**Labels:** `protocol`, `docs`, `community`  
**Outcome:** machine-readable manifest, expected outcomes, repetitions, cost and falsifier fields.  
**Evidence:** existing Authority Test represented in the format.

## 5. Add cryptographic event signing experiment

**Labels:** `lineage`, `security`, `rust`  
**Outcome:** optional signatures bound to canonical event hashes.  
**Non-goal:** production key management.  
**Evidence:** tamper, wrong-key and key-rotation fixtures.

## 6. Model stale negative memory

**Labels:** `memory`, `psychology`, `research`  
**Outcome:** claim lifecycle showing how “tool X failed” expires and is revalidated.  
**Evidence:** simulation where environment repair reverses a stale claim.

## 7. Build a harness adapter contract, not an adapter

**Labels:** `adapter`, `architecture`, `protocol`  
**Outcome:** minimal provider-neutral input/output/events contract for external harness runs.  
**Non-goal:** five vendor integrations.  
**Evidence:** two synthetic harness implementations satisfy the same contract.

## 8. Add TOCTOU protection between evaluation and promotion

**Labels:** `kernel`, `security`, `artifact`  
**Outcome:** promotion proves that the executed artifact hash equals the evaluated artifact hash.  
**Evidence:** mutation-after-evaluation attack must fail.

## 9. Independent Authority Test reproduction

**Labels:** `replication`, `good first issue`, `documentation`  
**Outcome:** run on a clean OS/container and publish exact environment plus result.  
**Evidence:** hashes, commands, failures and time-to-first-result.

## 10. Design an evolutionary-productivity metric

**Labels:** `evaluation`, `research`, `help wanted`  
**Outcome:** distinguish task performance from ability to produce stronger verified descendants.  
**Evidence:** at least two counterexamples where the best task performer is not the best parent.

## Triage rule

Every issue owner must be able to answer:

- what artifact will exist when this closes;
- how a reviewer determines success;
- which trusted boundary it changes;
- what is explicitly outside scope.
