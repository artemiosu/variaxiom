# Memory and Knowledge Lifecycle

## Memory is not a bag of text

Persistent memory is a set of claims and procedures with evidence histories. A model-generated sentence is not promoted merely because it sounds general.

## Memory classes

| Class | Example | Default inheritance |
|---|---|---|
| Working | current plan and tool outputs | never |
| Episodic | “request X failed with timeout at T” | retained as observation |
| Semantic | “API X requires header Y” | only with provenance and scope |
| Procedural | “workflow Z reliably deploys service A” | only after reproducible evaluation |
| Self-model | calibrated skill/cost envelope | periodically revalidated |
| Cultural | shared working notes between agents | filtered, non-authoritative |
| Lineage | parent, candidate, evidence, decision | immutable/tamper-evident |
| Constitutional | purposes, permissions, amendment rules | human-governed only |

## Claim record

A semantic memory record includes:

```text
claim_id
statement
source/provenance
observation_time
applicable_environment
confidence and calibration basis
supporting evidence ids
contradicting evidence ids
expiry or revalidation trigger
falsification conditions
data classification
```

## From episode to skill

```text
raw episode
 → normalized observation
 → repeated pattern
 → causal hypothesis
 → candidate procedure
 → clean-room trial
 → held-out trial
 → adversarial trial
 → promoted procedural package
```

The working agent cannot skip this pipeline.

## Negative knowledge

Claims such as “tool unavailable,” “API broken,” or “approach impossible” are environment-sensitive. They receive short TTLs and must retain the original error/context. The system should prefer:

```text
Tool X returned E in environment Y at time T
```

over:

```text
Tool X never works
```

## Contradiction and forgetting

Memory maintenance is deterministic where possible:

- deduplicate equivalent claims without erasing provenance;
- link contradictions rather than rewriting history;
- decay confidence on expiry;
- schedule revalidation based on value and volatility;
- deprecate procedures that fail current tests;
- keep tombstones and lineage for audit;
- compact derived summaries, never canonical evidence.

## Retrieval

Retrieval ranks by task relevance, evidence quality, environment compatibility, freshness, and authority—not semantic similarity alone. Context is assembled from minimal needed items. Full history remains outside the model context as inspectable artifacts.
