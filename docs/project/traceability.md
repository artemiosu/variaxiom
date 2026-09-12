# Requirement traceability

`project.yaml` is the machine-readable source of truth for status. This table must use the same
value for every requirement. `Implemented` means the named implementation exists locally;
`partial` means only part of the requirement or its evidence exists; `verified` requires the full
acceptance evidence to pass in the required environments. Documentation alone is not sufficient.

| Requirement | Specification/design | Implementation | Evidence | Status |
|---|---|---|---|---|
| REQ-CORE-001 | architecture overview §5 and accepted M2.2 spec | Python promotion gate; durable writer not implemented | `tests/test_promotion.py`, Authority Test, M2.2 specification council report; transaction fixtures planned | partial |
| REQ-CORE-002 | architecture overview §4 and accepted M2.2 authority boundary | module/trust-plane boundaries; writer not implemented | Authority Test plus M2.2 specification council report | partial |
| REQ-CORE-003 | M1.1/M2.1 specs, ADR 0009, and accepted M2.2 spec | Python/Rust protocol modules, disabled M2 stage-one through stage-eleven pipeline, sealed result types, private conformance history, and distinct non-authorizing public result APIs | shared v1 conformance plus all 252 frozen M2 cases and M2.2 specification council report; M2.2 schemas/fixtures planned | partial |
| REQ-AUTH-001 | constitution v1 | Python and Rust gates | ungranted-authority fixture and tests | implemented |
| REQ-AUTH-002 | M2.1 spec and grant schema | disabled exact-delta signed-grant verification in Python/Rust | v1 tests plus 21 frozen stage-eight grant failures and 54 later-boundary passes | partial |
| REQ-AUTH-003 | multi-agent architecture | not implemented | future cell lease tests | planned |
| REQ-TRUST-001 | constitution and M2.1 identity context | proposer/verifier checks | v1 self-check plus v2 adversarial manifest | partial |
| REQ-TRUST-002 | protected evaluation ADR | not isolated yet | future sandbox adversarial suite | planned |
| REQ-ID-001 | M2.1 spec, ADR 0010, principal/anchor/result schemas | disabled runtime identity graph, role, ownership, revocation, selector boundary, and sealed anchor-transition typestate in Python/Rust | accepted 252-case identity/transition corpus, replay-anchor mutation regression, API sealing probes, clean clone, CI, and implementation council report | partial |
| REQ-SIG-001 | M2.1 spec, ADR 0010, signature and result schemas | disabled Python/Rust runtime target/key binding, strict Ed25519, and selector verification | golden signatures, 252-case corpus, 19 Wycheproof vectors, cross-runtime tests, clean clone, CI, and implementation council report | partial |
| REQ-EVID-001 | M1.1/M2.1 conformance specs | Python/Rust exact candidate/artifact evidence binding | v1 artifact mismatch plus frozen v2 adjacent-candidate and stage-ten policy tests | implemented |
| REQ-EVID-002 | evaluation framework | bootstrap evidence objects | v1/v2 schemas and exact-candidate signed base fixture | partial |
| REQ-EVID-003 | evaluation framework | policy documentation only | future calibrated-evidence tests | planned |
| REQ-PROM-001 | constitution, M1.1, and M2.1 | Python/Rust pure gates plus disabled stage-ten/eleven pipeline and separate evaluate/verify/replay results | repeated v1 tests, 51 exact cross-language v2 policy decisions, 49 stage-eleven results, and exact always-non-authorizing public result tests | partial |
| REQ-PROM-002 | lineage architecture and accepted M2.2 spec | append-only Python ledger; SQLite rejected-decision persistence not implemented | rejected Authority Test lineage and M2.2 specification council report; M2.2 fixtures planned | partial |
| REQ-LINE-001 | data model and M1.1 | artifact store/canonical hashing | artifact and conformance tests | implemented |
| REQ-LINE-002 | event-sourced lineage ADR and accepted M2.2 spec/ADR 0011 | Python hash-chain ledger; transactional store not implemented | tamper and JSONL-framing tests plus M2.2 specification council report; SQLite fault fixtures planned | partial |
| REQ-ROLL-001 | constitution v1 and accepted M2.2 reservation contract | Python/Rust gate checks; durable reservation not implemented | missing-target tests plus M2.2 specification council report; M2.2 rollback fixtures planned | partial |
| REQ-ROLL-002 | accepted M2.2 append-only rollback contract | not implemented | M2.3 rollback drill planned | planned |
| REQ-OPS-001 | constitution/M2.1 resource limits | candidate cost gate plus disabled M2 stage-one/two resource boundaries | v1 budget, frozen v2 exact-limit/+1 cases, and Python/Rust M2 wire/structure/context tests | partial |
| REQ-OPS-002 | threat model and accepted M2.2 operator writer/rollback boundary | not implemented | specification council report; future pause/revoke/recovery tests | planned |
| REQ-OPS-003 | security/non-goals and accepted M2.2 no-ambient-effects contract | deny-by-default design | specification council report; future sandbox, writer-handle, and operator tests | partial |
| REQ-OBS-001 | observatory architecture and accepted M2.2 post-root-finalization hooks | not implemented | specification council report; future OpenTelemetry contract tests | planned |
| REQ-REP-001 | reproducibility guide | bootstrap/verify scripts | independent public clean-clone report at `e2a6a0f`, CI run `34062266427` | verified |
| REQ-REP-002 | architecture principles and accepted M2.2 replay/rebuild contract | deterministic demo inputs | demo reproducibility tests and specification council report; SQLite replay/fault fixtures planned | partial |
| REQ-CTX-001 | context index | repository context pack | repository verifier link checks | implemented |
| REQ-CTX-002 | specification workflow | this table and specs | repository verification plus review | implemented |
| REQ-CTX-003 | context index policy | source-controlled normative docs | deletion/rebuild policy review | partial |

Update this table in the same change that alters a requirement, public contract, implementation
status, or evidence path.
