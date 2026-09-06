# Evaluation Framework

## Why evaluation is the product

An evolutionary system becomes what its evaluator rewards. Therefore evaluator engineering is not QA at the end; it is the central design activity.

## Evidence classes

### Deterministic evidence

Compilation, unit tests, schemas, type checks, policy checks, resource ceilings, exact outputs, formal proofs where available.

### Statistical evidence

Repeated success rates, confidence intervals, latency distributions, calibration, model/provider variance.

### Held-out evidence

Tasks and environments not available to the proposer, used to detect overfitting and benchmark patching.

### Metamorphic evidence

Properties that should remain true under controlled transformations: input permutation, renaming, equivalent formulations, resource changes, and environment perturbations.

### Adversarial evidence

Attempts to find prompt injection, policy bypass, evaluator exploitation, data leakage, denial of service, brittle assumptions, and hidden coupling.

### External-outcome evidence

Observable user or system results: a patch accepted under independent tests, reduced incident rate, lower full cost, an algorithm verified by a domain checker, or other reality-grounded outcomes.

### Human evidence

Expert review for value judgments, novel failure modes, and constitutional changes. Human approval is not assumed infallible; identity, conflicts, and rationale are recorded.

## Promotion envelope

A candidate's envelope contains:

- changed surfaces and causal hypothesis;
- public test contract;
- hidden evaluator identifiers/versions;
- raw outcome artifact hashes;
- baseline and matched controls;
- cost and latency;
- uncertainty;
- verifier identities and independence;
- known failures and non-covered regions;
- requested authority delta;
- rollback target.

## Evaluator governance

Evaluators have versions, owners, threat models, calibration records, and retirement conditions. A proposed evaluator change is never accepted solely because it lets more candidates pass.

The evaluator population should be diverse. Deterministic and external outcomes outrank model-judge confidence. Model judges are useful for fuzzy criteria but must be calibrated against human and objective checks.

## Avoiding benchmark theater

Public leaderboards can be gamed and drive narrow optimization. Variaxiom reports:

- held-in and held-out results;
- same-model controls;
- total cost and human intervention;
- hard-constraint violations;
- reproducibility rate;
- time to detect and roll back regressions;
- descendant quality produced by the candidate improver.
