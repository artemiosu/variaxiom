# Security Policy

Variaxiom treats security as an architectural boundary, not a model instruction.

## Supported versions

The project is pre-alpha. Only the latest `main` branch is currently maintained. No production security guarantee is made.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities that could expose secrets, escape a sandbox, corrupt lineage, bypass promotion, reveal hidden evaluators, or escalate authority.

Until GitHub private vulnerability reporting is enabled, contact the repository owner through the verified contact channel on the GitHub profile and use the subject `Variaxiom security report`. Include:

- affected commit/version;
- threat model and impact;
- minimal reproduction in a safe environment;
- whether the issue is already public;
- suggested mitigation, if known.

Please allow coordinated disclosure. The project will acknowledge receipt, triage severity, preserve evidence, and publish a fix/advisory when safe.

## Trust model

The following are untrusted by default:

- model output;
- generated code;
- downloaded skills, plugins, and dependencies;
- external web content and tool responses;
- working-agent memory;
- candidate-supplied evaluation results;
- claims that a change is an improvement.

The following belong outside the editable phenotype:

- constitutional policy;
- authority grants and secret broker;
- hidden evaluators;
- promotion decision logic;
- append-only lineage verification;
- pause/revoke/rollback controls.

## Non-negotiable controls

- No candidate promotes itself.
- No authority escalation is inferred from task success.
- No secret is placed in model-readable context unless its exact use is explicitly delegated.
- No generated executable receives ambient host access.
- No hidden evaluator is readable by the candidate it evaluates.
- Every promotion has an addressable rollback target.
- Every spawned worker has a finite budget and termination condition.
- Audit evidence must survive process failure and candidate rejection.

## Responsible scope

Variaxiom does not accept deployable features designed for unauthorized persistence, stealth, uncontrolled replication, credential theft, security-control evasion, self-directed financial survival, or autonomous acquisition of infrastructure. Defensive simulations must be isolated, clearly labeled, and incapable of affecting third parties.

## Known bootstrap limitations

The current Python reference demo does **not** execute arbitrary untrusted code and is not a sandbox. Its evaluator is a trusted deterministic demonstration. The hash-chained JSONL ledger is tamper-evident, not a Byzantine or hardware-rooted log. Filesystem permissions, identity, signatures, remote attestation, confidential computing, and distributed consensus are future work. See the [threat model](docs/architecture/threat-model.md).
