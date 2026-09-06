# System Model and Lifecycle

## The digital organism analogy, made precise

Biological language is useful only when tied to engineering responsibilities.

| Biological metaphor | Variaxiom mechanism | Important limit |
|---|---|---|
| Genome | Versioned inheritable component graph | Not literal DNA and not a single prompt |
| Phenotype | Runnable composition under a model/environment | Behavior depends on environment and leases |
| Soma | Task-local agents and state | Disposable and non-heritable by default |
| Germline | Promotion-controlled inherited packages | Governed, not autonomous reproduction |
| Metabolism | Budgeted conversion of compute into verified external value | No terminal drive to earn or survive |
| Immune system | Isolation, policy, adversarial evals, anomaly detection | Critics can also fail and require evaluation |
| Organogenesis | Generated and certified tools/skills | No direct generated-code execution on host |
| Apoptosis | Worker termination and artifact cleanup | Evidence is retained even when workers die |
| Evolution | Variation, inheritance, independent selection | Requires multiple variants and generations |

## Lifecycle stages

### Stage 0 — substrate

Models, compute, storage, sandboxing, owner identity, and a reproducible build exist.

**Gate:** a clean machine can initialize and verify the seed.

### Stage 1 — zygote

A minimal kernel, one phenotype, one evaluator, and one complete task loop exist.

**Gate:** one externally useful result is produced and its trace is replayable.

### Stage 2 — boundary

Authority, identity, trust domains, and resource limits are explicit.

**Gate:** no worker has ambient host/network/secret authority.

### Stage 3 — genome

Skills, tools, workflows, policies, and tests are versioned and content-addressed.

**Gate:** the phenotype can be rebuilt from the recorded genotype.

### Stage 4 — homeostasis

The system detects errors, retries within budgets, rolls back, and preserves evidence.

**Gate:** injected faults do not corrupt trusted lineage.

### Stage 5 — learning

Episodes become hypotheses; hypotheses become candidate knowledge; only validated candidates become procedural or semantic memory.

**Gate:** a transient outage cannot become an unqualified permanent belief.

### Stage 6 — organogenesis

The system creates a new bounded tool or skill for a capability gap.

**Gate:** the component passes package, sandbox, contract, security, and authority checks.

### Stage 7 — multicellularity

Specialized workers coordinate through typed contracts and shared artifacts.

**Gate:** the organization outperforms a single agent under the same total budget.

### Stage 8 — inheritance

A descendant constructed in a clean environment retains a promoted capability.

**Gate:** improvement survives process, session, and machine replacement.

### Stage 9 — population evolution

An archive stores diverse lineages; variants are selected against held-out tasks and hard constraints.

**Gate:** at least one descendant improves the Pareto frontier without critical regression.

### Stage 10 — ecological value

The system repeatedly creates external value greater than full cost and risk reserve.

**Gate:** positive risk-adjusted evolutionary surplus over a defined period.

### Stage 11 — meta-evolution

Mutation operators, experiment allocation, parent selection, and evaluation strategies become candidate-editable surfaces.

**Gate:** the new improver produces better independently verified descendants per unit cost than its ancestor.

### Stage 12 — recursive technology loop

The system contributes to improvements in harness, data, model adaptation, inference, and compute tooling.

**Gate:** several independent generations show accelerating verified productivity, not merely external model upgrades.

## Stage order matters

Reproduction before boundaries and budgets is uncontrolled proliferation. Persistent memory before provenance and invalidation is accumulating delusion. Self-modification before protected evaluators is reward hacking. Scale before unit economics is expensive noise.

Variaxiom therefore uses stage gates rather than a feature checklist.
