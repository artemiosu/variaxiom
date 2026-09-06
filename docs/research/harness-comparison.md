# Harness Landscape Review — September 6, 2026

## Method

This is an architecture review, not a feature contest. The projects were studied to identify:

- what they prove is useful;
- which trust boundary they assume;
- where memory and skills become persistent;
- whether changes are independently evaluated and inherited;
- how tool execution, sandboxing, and authority are separated;
- what Variaxiom must not blindly copy.

Primary sources are preferred: official documentation, repositories, and research papers. Repository popularity is not treated as proof of safety or technical superiority.

## Summary matrix

| System | Strongest contribution | Boundary/weakness relevant to Variaxiom | Variaxiom response |
|---|---|---|---|
| Claude Code | Mature coding loop, hooks, skills, subagents, context and permission controls | Memory/instructions are context, not enforced configuration; it is an executor rather than an inherited evolution system | Put invariants in deterministic kernel; use Claude through an adapter as a phenotype organ |
| OpenAI Codex | Strong workspace sandbox/approval model, visible terminal execution, configurable permissions | Sandboxing/approval controls action, but does not define evolutionary lineage or proof of inherited improvement | Reuse the separation of sandbox and approval concept; add candidate/evidence/promotion/lineage |
| DeepSeek Harness | Radical composability: model, tools, sessions, storage, loop, UI as plugins | “Everything is a plugin” reduces a privileged core; composition creates compatibility/default UX costs; developer preview is evolving | Keep most of system evolvable, but retain a tiny non-plugin constitutional microkernel and curated reference phenotype |
| Hermes Agent | Persistent memory and built-in loop that creates/refines skills from experience | Reflection-to-memory/skill is only as reliable as its write-approval and evaluation; durable text can preserve environment-specific errors | Episode → hypothesis → independent tests → promoted skill; no direct working-memory inheritance |
| OpenClaw | Memorable product, local/self-hosted gateway, channels, tools, skills, plugins, strong accessibility | Personal-assistant trust model; sandbox is opt-in; host exec and broad gateway reach can create large blast radius | Per-cell trust domains, sandbox by construction, brokered secrets, no multi-user assumptions hidden in configuration |
| Darwin Gödel Machine | Archive of diverse self-modified coding agents with empirical selection | Benchmark-bounded, experimental, human-supervised; empirical fitness is still evaluator-dependent | Generalize archive/lineage while hard-separating authority and protected evaluation |
| Self-Harness | Weakness mining → bounded proposal → held-in/held-out regression validation | Self-editable surfaces still need an external security boundary; regression suites remain incomplete | Make editable surfaces explicit; place permission/security and promotion outside the loop |
| AlphaEvolve | LLM variation + automated evaluators + program database/evolutionary selection | Works best when objective quality is cheap and unambiguous; many real tasks lack such evaluators | Treat evaluator engineering as the core product and support multiple evidence classes |

## Claude Code

Official documentation presents an agent loop with file, shell, tools, skills, subagents, memory, hooks, and permissions. Its most important lesson for Variaxiom is explicit in the memory documentation: `CLAUDE.md` and auto memory are loaded as context, not enforced configuration; blocking an action requires hooks or permission controls.

**Strengths to preserve**

- excellent developer ergonomics and repository navigation;
- compact skill packaging and task-specific subagents;
- hooks as deterministic interception points;
- practical permission/tool restriction surfaces;
- visible artifacts and terminal feedback.

**Boundary**

Claude Code optimizes a working session. It does not provide a general protocol in which a skill/harness mutation receives independent evidence, becomes a versioned inheritable genotype, competes in a population, and can be causally attributed across generations.

**Variaxiom decision**

Claude Code can be a builder/explorer adapter. Its memory can produce candidate observations, but never constitutional authority or automatic germline updates.

Sources:

- https://docs.anthropic.com/en/docs/claude-code
- https://docs.anthropic.com/en/docs/claude-code/memory
- https://docs.anthropic.com/en/docs/claude-code/hooks
- https://docs.anthropic.com/en/docs/claude-code/skills
- https://docs.anthropic.com/en/docs/claude-code/sub-agents

## OpenAI Codex

Codex cleanly distinguishes sandbox boundaries from approval policy. Official documentation states that default local execution uses an OS-enforced sandbox with network disabled, while approval determines when boundary-crossing is considered. Auto-review can route an escalation request to a separate reviewer without changing the underlying sandbox.

**Strengths to preserve**

- workspace-scoped execution and network boundaries;
- explicit approval semantics;
- visible command/tool transcript;
- support for MCP and developer-configurable permissions;
- an emerging separation between actor and escalation reviewer.

**Boundary**

The security model governs actions of a current agent. It does not by itself answer whether a proposed self-change improves descendants, whether evaluators are protected from the candidate, or how multiple lineages are archived.

**Variaxiom decision**

Model sandbox and authority approval remain separate. Auto-review evidence may inform a lease decision, but a reviewer model cannot override a hard deny or constitutional rule.

Sources:

- https://developers.openai.com/codex/cli
- https://developers.openai.com/codex/sandboxing
- https://developers.openai.com/codex/agent-approvals-security
- https://developers.openai.com/codex/sandboxing/auto-review

## DeepSeek Harness

DeepSeek Harness introduces a highly compositional Cordis architecture in which models, tools, skill/session/storage systems, sandbox, loop, scheduling, and UI can be plugins. Typed events and reversible registration effects are attractive for experimentation.

**Strengths to preserve**

- replaceable components and explicit composition;
- profile/bundle architecture;
- typed event orientation;
- low friction for third-party experimentation;
- a clear category statement: “Everything is a plugin.”

**Boundary**

Its official architecture says even the model adapter, tool registry, session log, and agent loop are replaceable and there is no privileged core to patch. That is powerful for extensibility, but a governed self-evolving system still needs a small layer the candidate cannot replace while being judged. Community feedback also highlights the user-side cost of radical composability: a curated, tested, one-command default is needed for most adopters.

The September 2026 project is explicitly a developer preview with evolving APIs and rough edges, so treating its current interfaces as a stable foundation would be premature.

**Variaxiom decision**

Adopt “almost everything can vary,” not “every enforcement mechanism is a peer plugin.” The promotion kernel, lease verification, protected evaluator boundary, and lineage integrity stay outside candidate control. Ship a curated reference phenotype, not only a toolbox of components.

Sources:

- https://www.deepseek.com/harness/en/
- https://github.com/deepseek-ai/deepseek-harness
- https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md
- https://github.com/deepseek-ai/deepseek-harness/discussions/326

## Hermes Agent

Hermes presents persistent memory and skills as a learning loop: durable facts remain in memory; longer procedures load as skills; a background review may save/update them, and a write-approval setting can stage changes for human review.

**Strengths to preserve**

- first-class cross-session continuity;
- distinct memory versus longer procedural skills;
- user-visible learning behavior;
- an ecosystem and practical self-hosted deployment story;
- optional approval for writes.

**Boundary**

A background reflection can formulate a useful candidate, but its confidence is not an independent evaluator. Without strong provenance, environment scope, TTL, clean-room reproduction, and held-out tests, durable memories can encode a transient outage or a persuasive but incorrect generalization.

**Variaxiom decision**

Retain the learning UX but split the storage classes. Background review writes episodic claims and staged candidates only. A production procedural skill is a proof-carrying package promoted by independent evidence.

Sources:

- https://hermes-agent.nousresearch.com/docs/
- https://hermes-agent.nousresearch.com/docs/user-guide/features/memory
- https://hermes-agent.nousresearch.com/docs/user-guide/features/skills
- https://hermes-agent.nousresearch.com/docs/developer-guide/agent-loop

## OpenClaw

OpenClaw demonstrates exceptional product communication: a memorable mascot, a concrete promise, one gateway, self-hosting, and availability inside chat channels people already use. The capabilities taxonomy also clearly distinguishes tools, skills, and plugins.

**Strengths to preserve**

- instantly understandable user outcome;
- local-first ownership narrative;
- channels that make the agent observable in everyday life;
- broad plugin/skill ecosystem;
- strong community identity.

**Boundary**

Official security documentation says sandboxing is opt-in and, without it, tool execution may resolve to the gateway host. The documented default trust model is a personal assistant/single trusted operator, not hostile multi-tenant isolation. `exec` remains a mutating shell surface wherever its host permits. This is acceptable only when users understand the trust envelope; it is not an appropriate default for self-generated evolutionary components.

**Variaxiom decision**

Every candidate and worker receives its own lease and isolated execution domain. Skills never imply tool permission. Secrets are brokered. Variaxiom borrows the communication clarity—not the broad default blast radius.

Sources:

- https://github.com/openclaw/openclaw
- https://openclaw.ai/blog/introducing-openclaw
- https://docs.openclaw.ai/tools
- https://docs.openclaw.ai/tools/skills
- https://docs.openclaw.ai/gateway/security
- https://docs.openclaw.ai/gateway/sandboxing
- https://docs.openclaw.ai/tools/exec

## Research systems

### Darwin Gödel Machine

DGM empirically validates self-modified coding agents and maintains an archive/tree instead of repeatedly overwriting one active agent. The March 2026 revision reports improvements on SWE-bench and Polyglot under sandboxing and human oversight. Its most important transferable idea is the archive of diverse stepping stones.

Source: https://arxiv.org/abs/2505.22954

### Self-Harness

The August 2026 revision formalizes three stages: verifier-grounded weakness mining, bounded/minimal harness proposals, and held-in/held-out validation. It reports gains across nine model/benchmark combinations. It also reinforces Variaxiom's requirement that permission and security layers remain outside the editable loop.

Source: https://arxiv.org/abs/2606.09498

### AlphaEvolve

AlphaEvolve combines LLM-generated program variants with objective automated evaluators and a program database that determines future parents. It demonstrates that recursive technological loops are most credible where candidates can be executed and scored objectively. Google reports applications to data-center scheduling, hardware, AI training, kernels, and mathematics.

Source: https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/

## Cross-cutting weaknesses Variaxiom targets

1. **Session continuity is mistaken for verified learning.**
2. **Textual instructions are mistaken for hard policy.**
3. **Generated tools inherit overly broad runtime authority.**
4. **The proposer participates too directly in its own acceptance.**
5. **Benchmarks omit authority, cost, maintainability, and metaproductivity.**
6. **One active lineage overwrites useful diversity.**
7. **Subagent count grows faster than coordination quality.**
8. **Tool/skill catalogs inflate context and attack surface.**
9. **Evaluator changes are not governed as carefully as agent changes.**
10. **Compelling “self-improving” branding outruns reproducible proof.**

## Positioning conclusion

Variaxiom should not advertise itself as a replacement terminal agent. It should become the **proof and inheritance layer for systems that change agents**.

A useful integration claim is:

> Bring a model, an agent, or a harness. Variaxiom turns proposed changes into versioned candidates, tests them in protected environments, and promotes only evidence-backed descendants.
