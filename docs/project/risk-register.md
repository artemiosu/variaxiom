# Risk Register

| ID | Risk | Likelihood | Impact | Leading indicator | Mitigation / response |
|---|---|---:|---:|---|---|
| R1 | Evaluator rewards loopholes instead of real improvement | High | Critical | candidates gain score without external outcome gain | hidden/metamorphic/adversarial evals, evaluator governance, external outcomes |
| R2 | Memory accumulates false or stale rules | High | High | contradiction rate and failed replay rise | provenance, TTL, clean-room replay, negative-claim revalidation |
| R3 | Generated tool escapes or receives overbroad authority | Medium | Critical | undeclared I/O, network, secret access | WIT leases, isolation tiers, brokered secrets, red-team review |
| R4 | Founder overbuilds architecture before a viral proof | High | High | months of code with no runnable narrative | maintain one-command vertical slice; publish experiments early |
| R5 | Project is perceived as AGI hype without substance | High | High | discussion centers on “singularity” rather than results | lead with proof-gated demo, publish limitations, avoid inevitability claims |
| R6 | Name conflict or trademark challenge | Low/Medium | Medium | similar claimant appears | preliminary clearance now; formal USPTO/WIPO/EUIPO/domain review before investment |
| R7 | Dependency/framework churn | High | Medium | adapters break frequently | provider-neutral ports; core schemas independent of third parties |
| R8 | Rust/Python split slows contributors | Medium | Medium | duplicated logic diverges | shared fixtures, protocol schemas, clear ownership, bootstrap path in Python |
| R9 | Community receives too many low-quality AI-generated PRs | High | High | review queue and maintainer burnout | issue claiming, evidence template, PR limits, DCO, staged contributor rights |
| R10 | Security branding creates unrealistic trust | Medium | High | users deploy pre-alpha with secrets | explicit warnings, secure-by-default releases, no arbitrary execution in seed |
| R11 | Stars grow but contributors/users do not retain | Medium | Medium | high stars, low clone/demo/repeat activity | track activation, weekly active experimenters, contributor conversion |
| R12 | No objective evaluator for broad tasks | High | High | model judges dominate evidence | begin in code/algorithm domains; mix external/human outcomes; mark uncertainty |
| R13 | Population collapses into near-identical variants | Medium | High | lineage/behavior diversity drops | archive, novelty metrics, protected exploration budget |
| R14 | Multi-agent coordination costs exceed gains | High | Medium | cost per accepted candidate rises with workers | matched-budget controls, spawn tokens, deduplication, apoptosis |
| R15 | Hosted model updates confound causal attribution | High | Medium | gains disappear or cannot be replayed | same-time controls, fingerprints, local open-model baselines |
| R16 | Governance capture or reviewer collusion | Low/Medium | Critical | same people control proposal/eval/promotion | role separation, public RFCs, reviewer diversity, signed decisions |
| R17 | Funding pushes premature commercialization | Medium | High | roadmap shifts to demos without evaluation rigor | chartered non-negotiables, milestone-based sponsorship, transparent conflicts |
| R18 | “Open source” leaks dangerous operational defaults | Medium | High | users enable broad host execution | bounded reference components, responsible scope, dangerous features excluded |
| R19 | Signing keys are mistaken for principals or authority | Medium | Critical | self-generated or aliased keys pass role/independence checks | trusted principal/key/role snapshots, self-certifying key IDs, alias tests, no authority from signatures alone |
| R20 | Valid signatures are replayed after expiry, revocation, or against adjacent objects | Medium | Critical | old grants authorize new candidates or mutable trust lookups change replay | exact subject/audience/digest binding, explicit evaluation time, committed revocation snapshot, replay tests |
| R21 | A stale, retried, or partially committed writer corrupts selected lineage | Medium | Critical | duplicate events, head gaps, orphan rollback state, or divergent projections | SQLite FULL/WAL transaction, full-operation idempotency digest, exact dual-head CAS, crash injection, shadow projection comparison |
| R22 | Local database replacement rolls history back to an internally valid older root | Medium | Critical | verified local chain head is older than an independently retained receipt/root | mandatory writer-open comparison to operator-retained root and artifact-complete backup; transparency witness deferred |
| R23 | Crash recovery is authorized correctly but the fresh recovery operator is not durably attributed in lineage history | Medium | High | root recovery can be proven from pending intent, but only the original event writer appears in retained lineage facts | emit structured host-control audit for every recovery attempt; keep it explicitly non-authorizing; freeze a durable root-custodian recovery-audit design before production operations claim attributable recovery |
