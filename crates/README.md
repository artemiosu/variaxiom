# Trusted Rust kernel scaffold

The Rust workspace is the intended home of the small trusted computing base:
protocol types, promotion invariants, capability leasing, and signed lineage.
It deliberately excludes model calls, planning, retrieval, generated code, and
provider SDKs.

The first repository build environment did not contain a Rust toolchain, so the
Python reference implementation was executed and tested here while this
zero-third-party-dependency Rust scaffold received source review only. The
GitHub CI workflow is configured to compile and test it on a standard runner.
Treat the Rust code as pre-alpha until that CI has passed in the public repo.
