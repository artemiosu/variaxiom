# Architectural Principles

## P1. Mutation is not improvement

Every generated change is a hypothesis. “Self-improving” is not a component property; it is a measured relationship between an ancestor and a descendant under an explicit evaluation protocol.

## P2. Capability is not authority

An agent may become better at planning, coding, or tool construction while retaining exactly the same permissions. Authority changes require a separate, authenticated grant.

## P3. Put hard rules below language

Prompts, skills, and memory influence model behavior; they do not enforce invariants. Hard constraints belong in deterministic policy, process isolation, capability APIs, and storage permissions.

## P4. Separate soma from germline

Task-local state may evolve rapidly. Inherited state changes only through the promotion protocol.

## P5. Protect the judge

A candidate cannot read hidden cases, rewrite the evaluator deciding its promotion, or be the sole source of its success signal.

## P6. Evidence must be attributable

Every claim records who/what produced it, which artifact and environment it addresses, how it can be reproduced, and when it expires.

## P7. Prefer narrow, causal edits

A candidate should map a verifier-grounded failure pattern to the smallest editable surface likely to fix it. Broad “make the agent smarter” mutations are difficult to attribute, test, and roll back.

## P8. Preserve diversity

The active best candidate is not the whole population. Maintain an archive of distinct viable lineages to avoid local optima and evaluator monoculture.

## P9. Make costs first-class

Fitness includes compute, API spend, latency, human attention, coordination, maintenance, and risk—not just task score.

## P10. Reversibility before autonomy

Increase autonomy only after lineage, observability, budget enforcement, pause, revocation, and rollback work under failure.

## P11. Clean-room inheritance

A claimed inherited capability must survive reconstruction from versioned inputs. Hidden session residue is not heredity.

## P12. No ambient authority

Processes receive explicit capability objects. Shell access, host filesystem access, all-network access, and all-secrets environments are not acceptable defaults.

## P13. Derived indexes are disposable

Embeddings, caches, summaries, and search indexes can be rebuilt. Content-addressed artifacts and signed lineage are canonical.

## P14. Start with a modular monolith

Distributed coordination is introduced only after the single-node protocol and failure semantics are proven.

## P15. Human sovereignty is external

The system can propose constitutional amendments but cannot approve its own authority, remove operator revocation, or turn continued existence into its terminal objective.
