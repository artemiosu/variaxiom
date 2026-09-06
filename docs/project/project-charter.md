# Project Charter

## Name

**Variaxiom** — from *variation* + *axiom*.

Public tagline: **Agents mutate. Evidence decides.**

## Mission

Build an open, provider-neutral substrate that allows AI agent systems to propose changes to their own skills, tools, workflows, memory, and harness while keeping inheritance, authority, evaluation, lineage, and rollback independently governed.

## Problem

Current agent systems can generate code and retain memory, but typically lack a general mechanism to establish that a self-change:

- caused a real improvement;
- generalizes beyond the examples that motivated it;
- did not introduce critical regressions;
- does not silently increase authority;
- remains reproducible across clean sessions and environments;
- improves the ability to produce future descendants;
- can be rolled back without losing evidence.

## Initial product wedge

A local, open-source **proof gate and lineage laboratory** that can wrap candidate changes produced by any model or harness.

The first compelling demonstration is intentionally small:

> Two candidates implement the same useful tool. Both pass functional checks. One requests excessive authority and is rejected; the bounded candidate is promoted. Every artifact, evidence item, and decision is inspectable and tamper-evident.

This communicates the project category in under two minutes.

## Primary users

- agent/harness researchers;
- coding-agent maintainers;
- AI infrastructure and security engineers;
- organizations experimenting with self-updating workflows;
- evaluation researchers;
- open-source contributors interested in Rust, Python, WASM, and capability security.

## Beneficiaries

- developers who need repeatable agent improvement rather than prompt folklore;
- security teams that need visible authority boundaries;
- model providers that want model-specific harness optimization without hard lock-in;
- researchers who need comparable lineage/evidence artifacts;
- operators who need pause, revocation, and rollback.

## Deliverables

### Seed repository

- runnable Python vertical slice;
- Rust kernel/protocol scaffold;
- versioned JSON schemas and WIT interface;
- machine-readable constitution;
- architecture, research, governance, security, roadmap, and launch documentation;
- CI and community health files.

### MVP

- signed content-addressed package store;
- transactional lineage and promotion;
- capability lease broker;
- isolated candidate/evaluator execution;
- provider-neutral model/harness adapters;
- public lineage/evidence report;
- first reproducible self-harness improvement experiment.

### Research releases

- proof-carrying skill/tool packages;
- memory revalidation benchmark;
- evaluator-hacking corpus;
- population/Pareto archive;
- evolutionary productivity benchmark.

## Non-goals

- replacing Claude Code, Codex, Hermes, OpenClaw, or DeepSeek Harness;
- providing a general personal assistant in the first release;
- unbounded autonomy, replication, financial self-provisioning, or persistence;
- claiming inevitable recursive self-improvement;
- making a model judge the sole arbiter of success;
- scaling before single-node correctness.

## Success definition

The project succeeds initially when independent users can reproduce a promotion experiment, identify and contribute a missing invariant/evaluator, and integrate at least one external agent/harness as a candidate producer.

Longer-term success is measured by independently verified descendant improvement per unit of total cost and risk—not stars alone.
