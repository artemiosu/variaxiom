# ADR-0003: WIT/WebAssembly component boundary for generated tools

- Status: Accepted with caveats
- Date: 2026-09-06

## Context

Generated tools need a portable, typed, deny-by-default execution boundary. Raw host shell or language package imports grant excessive authority.

## Decision

Use WIT and the WebAssembly Component Model as the preferred ABI for bounded generated tools, hosted by Wasmtime. Expose only lease-backed host imports. Use stronger OCI/gVisor/Firecracker-class isolation for workloads requiring browsers, native toolchains, or unsupported system interfaces.

## Consequences

Positive: explicit capabilities, portability, reproducible packaging, language diversity.

Negative: evolving standards, ecosystem gaps, runtime attack surface, limited fit for rich OS workloads. WASM is an isolation layer, not a complete security model.
