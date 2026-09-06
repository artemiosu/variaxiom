# GitHub Copilot instructions

Follow `AGENTS.md` and the constitutional invariants in `constitution/`.

- Preserve proposer/verifier/selector/deployer separation.
- Never turn increased capability into implicit authority.
- Bind evidence and rollback targets to exact content digests.
- Keep the trusted Rust kernel deterministic and free of ambient authority.
- Prefer small standard-library Python changes and explicit schemas.
- Add or update tests for every policy change; run `bash scripts/verify.sh`.
- Do not propose persistence, covert propagation, permission bypass, autonomous purchasing, or
  resistance to operator shutdown.
