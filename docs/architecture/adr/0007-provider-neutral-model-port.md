# ADR-0007: Models and external harnesses behind provider-neutral ports

- Status: Accepted
- Date: 2026-09-06

## Context

Model APIs and agent frameworks change quickly. Tying lineage, evidence, or security policy to one provider makes research results brittle and creates lock-in.

## Decision

Represent model invocation, tool use, trace capture, and external-harness control through versioned ports/adapters. Record provider/model identity as experimental metadata. No LangChain, CrewAI, Claude Code, Codex, Hermes, OpenClaw, or DeepSeek Harness type becomes a core domain type.

## Consequences

Positive: controlled comparisons, provider diversity, future replacement.

Negative: least-common-denominator pressure and adapter maintenance. Provider-specific features remain available through declared extensions rather than leaking into the kernel.
