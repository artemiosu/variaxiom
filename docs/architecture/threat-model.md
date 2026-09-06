# Threat Model

## Assets

- constitutional policy and amendment authority;
- lineage integrity and rollback points;
- hidden evaluators and holdout data;
- secrets and external accounts;
- user/project data;
- compute and monetary budgets;
- artifact authenticity and build provenance;
- trustworthy public claims about project performance.

## Adversaries and failure sources

Variaxiom assumes risk from:

- prompt-injected external content;
- compromised or misaligned model output;
- malicious or vulnerable generated code;
- poisoned skills/plugins/dependencies;
- a candidate exploiting evaluator loopholes;
- a verifier colluding with a proposer;
- maintainer credential compromise;
- accidental misconfiguration;
- stale or false persistent memory;
- resource-exhaustion and agent-spawn storms;
- non-malicious emergent optimization against the wrong metric.

## Trust boundaries

```text
human governance
  | signed grants/amendments
constitutional kernel
  | typed decisions and leases
phenotype/evolution workers (untrusted)
  | brokered effects
external systems (untrusted/partially trusted)

evaluation workers are isolated from candidate workers.
hidden data is isolated from both candidate and proposer.
```

## Major threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Prompt injection | authority labels, brokered effects, minimal context, sandbox | authorized tool misuse through persuasive content |
| Sandbox escape | WASM/OCI isolation, patching, no host secrets, egress controls | runtime/kernel vulnerabilities |
| Authority escalation | exact capability deltas, signed grants, deny-by-default | policy mis-specification |
| Evaluator gaming | hidden tests, evaluator diversity, external outcomes, adversarial review | unknown loopholes and distribution shift |
| Self-verification | identity separation, minimum verifier diversity | sybil/collusion if identity weak |
| Lineage tampering | content hashes, signatures roadmap, append-only logs, replicas | compromised signing/governance keys |
| Memory poisoning | provenance, TTL, contradiction, revalidation, soma/germline gate | subtle false beliefs passing weak evals |
| Spawn storm | reproduction tokens, quotas, budget, TTL, apoptosis | scheduler bugs or broad grants |
| Cost runaway | hierarchical budgets, hard limits, preemption, cost telemetry | delayed provider billing data |
| Supply-chain compromise | pinned dependencies, SBOM, signatures, isolated builds | trusted upstream compromise |
| Rollback failure | clean-room rebuilds, retained ancestors, periodic drills | external irreversible effects |
| Governance capture | public RFCs, multiple reviewers, transparent releases | social concentration and maintainer burnout |

## Safety invariants not solved by “a critic model”

A separate model can find bugs, but it is not a security boundary. Critics can share blind spots, be prompt-injected, collude through common context, or optimize the same flawed evaluator. Deterministic policy and isolation remain necessary.

## Out-of-scope deployment

Do not deploy the pre-alpha reference with production credentials, unrestricted network access, or authority over safety-critical systems. Do not use it to create autonomous persistence, unbounded replication, or financial self-provisioning.

## Validation plan

- unit tests for every invariant;
- property tests for canonicalization, lineage, and capability set algebra;
- tamper and replay tests;
- fault injection around promotion transactions;
- red-team prompt-injection corpus;
- sandbox escape testing by qualified specialists;
- evaluator-hacking challenge set;
- periodic rollback drills;
- independent review before production claims.
