# Architectural Anti-Patterns

## The immortal monolith

One process owns memory, tools, self-modification, evaluation, secrets, and deployment. Any compromise becomes total compromise.

## Prompt-as-policy

A Markdown instruction says “never do X,” but the runtime still exposes X. Guidance is not enforcement.

## Direct experience-to-skill writes

A single success or failure automatically changes inherited behavior. This converts noise and prompt injection into “learning.”

## Self-judging mutation

The agent edits code, writes the tests, runs them, interprets them, and deploys itself. No independent evidence exists.

## Giant tool prompt

Every tool schema and skill is always loaded into context. Cost, confusion, and attack surface grow with the ecosystem.

Use capability discovery and task-local loading instead.

## Unrestricted shell as the primitive

A raw shell plus host network, filesystem, and secrets is treated as a convenient universal tool. It is universal ambient authority.

## Swarm equals intelligence

Agents are spawned without budgets, ownership, deduplication, termination, or shared artifact contracts. Coordination cost dominates useful work.

## Scalar fitness

One benchmark score collapses security, cost, robustness, and generalization. The system learns to exploit the scalar.

## Active-version overwrite

A new candidate replaces the prior system without a retained lineage, reproducible build, or rollback drill.

## Microservices before semantics

Distributed infrastructure is introduced before promotion and evidence transactions are understood, multiplying failure modes.

## Autonomous metabolism as survival instinct

The system receives wallets and a terminal goal to fund or preserve itself. Budgeted operation under human governance is sufficient; autonomous self-preservation creates avoidable goal conflict.

## Branding before proof

A project claims “digital life” or “singularity” but lacks one reproducible demonstration. Public attention without falsifiable evidence creates distrust and contributor churn.
