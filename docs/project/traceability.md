# Requirement traceability

`project.yaml` is the machine-readable source of truth for status. This table must use the same
value for every requirement. `Implemented` means the named implementation exists locally;
`partial` means only part of the requirement or its evidence exists; `verified` requires the full
acceptance evidence to pass in the required environments. Documentation alone is not sufficient.

| Requirement | Specification/design | Implementation | Evidence | Status |
|---|---|---|---|---|
| REQ-CORE-001 | architecture overview §5 | Python promotion gate | `tests/test_promotion.py`, Authority Test | partial |
| REQ-CORE-002 | architecture overview §4 | module/trust-plane boundaries | Authority Test plus architecture review | partial |
| REQ-CORE-003 | M1.1/M2.1 specs and ADR 0009 | Python/Rust protocol modules and disabled M2 internal stage-one through stage-eleven pipeline; public two-phase API blocked on contract correction | shared v1 conformance plus all 237 frozen M2 cases exercised at their assigned boundary; 37 terminal statuses/codes/decisions/anchors match while unsafe positive authority flags are intentionally suppressed | partial |
| REQ-AUTH-001 | constitution v1 | Python and Rust gates | ungranted-authority fixture and tests | implemented |
| REQ-AUTH-002 | M2.1 spec and grant schema | disabled exact-delta signed-grant verification in Python/Rust | v1 tests plus 21 frozen stage-eight grant failures and 40 later-boundary passes | partial |
| REQ-AUTH-003 | multi-agent architecture | not implemented | future cell lease tests | planned |
| REQ-TRUST-001 | constitution and M2.1 identity context | proposer/verifier checks | v1 self-check plus v2 adversarial manifest | partial |
| REQ-TRUST-002 | protected evaluation ADR | not isolated yet | future sandbox adversarial suite | planned |
| REQ-ID-001 | M2.1 spec, ADR 0010, principal/anchor/result schemas | disabled runtime identity graph, role, ownership, revocation, and selector boundary in Python/Rust | accepted 252-case identity, alias, role, genesis, transition, non-authorizing result, replay-anchor binding, revocation, selector-role vectors, stage-five/eleven tests, and result-contract council report | partial |
| REQ-SIG-001 | M2.1 spec, ADR 0010, signature and result schemas | disabled Python/Rust runtime target/key binding, strict Ed25519, and selector verification | golden message/signature, accepted 252-case corpus, 19 Wycheproof vectors, stage-four/six/eleven and direct selector cases, and result-contract council report | partial |
| REQ-EVID-001 | M1.1/M2.1 conformance specs | Python/Rust exact candidate/artifact evidence binding | v1 artifact mismatch plus frozen v2 adjacent-candidate and stage-ten policy tests | implemented |
| REQ-EVID-002 | evaluation framework | bootstrap evidence objects | v1/v2 schemas and exact-candidate signed base fixture | partial |
| REQ-EVID-003 | evaluation framework | policy documentation only | future calibrated-evidence tests | planned |
| REQ-PROM-001 | constitution, M1.1, and M2.1 | Python/Rust pure gates plus disabled internal stage-ten/eleven pipeline; authority-safe public result contract pending | repeated v1 tests, 37 exact cross-language v2 decisions, and non-authorizing terminal implementation results | partial |
| REQ-PROM-002 | lineage architecture | append-only Python ledger | rejected Authority Test lineage | partial |
| REQ-LINE-001 | data model and M1.1 | artifact store/canonical hashing | artifact and conformance tests | implemented |
| REQ-LINE-002 | event-sourced lineage ADR | Python hash-chain ledger | tamper and JSONL-framing tests | partial |
| REQ-ROLL-001 | constitution v1 | Python/Rust gate checks | missing-target tests | partial |
| REQ-ROLL-002 | roadmap M2 | not implemented | future rollback drill | planned |
| REQ-OPS-001 | constitution/M2.1 resource limits | candidate cost gate plus disabled M2 stage-one/two resource boundaries | v1 budget, frozen v2 exact-limit/+1 cases, and Python/Rust M2 wire/structure/context tests | partial |
| REQ-OPS-002 | threat model | not implemented | future pause/revoke recovery tests | planned |
| REQ-OPS-003 | security/non-goals | deny-by-default design | future sandbox and operator tests | partial |
| REQ-OBS-001 | observatory architecture | not implemented | future OpenTelemetry contract tests | planned |
| REQ-REP-001 | reproducibility guide | bootstrap/verify scripts | independent public clean-clone report at `e2a6a0f`, CI run `34062266427` | verified |
| REQ-REP-002 | architecture principles | deterministic demo inputs | demo reproducibility tests | partial |
| REQ-CTX-001 | context index | repository context pack | repository verifier link checks | implemented |
| REQ-CTX-002 | specification workflow | this table and specs | repository verification plus review | implemented |
| REQ-CTX-003 | context index policy | source-controlled normative docs | deletion/rebuild policy review | partial |

Update this table in the same change that alters a requirement, public contract, implementation
status, or evidence path.
