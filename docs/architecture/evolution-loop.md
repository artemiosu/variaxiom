# Evolution Loop

## Objective

The loop seeks candidate systems that improve a Pareto frontier of externally verified properties while satisfying non-negotiable constraints.

```text
fitness = [task success, generalization, robustness, calibration,
           maintainability, evolutionary productivity,
           external value, -cost, -latency, -human attention]
```

Hard constraints are not weighted terms. A candidate that violates authority, evaluator integrity, lineage, or bounded reproduction is rejected regardless of task score.

## One generation

1. **Observe:** collect traces, costs, outcomes, and evaluator-level failures.
2. **Attribute:** distinguish terminal symptom from likely causal component.
3. **Hypothesize:** describe a narrow, falsifiable change and preserved behaviors.
4. **Diversify:** produce several structurally different candidates.
5. **Build:** create content-addressed artifacts in clean environments.
6. **Evaluate:** run held-in, held-out, metamorphic, adversarial, security, and budget checks.
7. **Compare:** use matched controls and uncertainty estimates.
8. **Select:** update a Pareto archive; do not overwrite all ancestors.
9. **Promote:** pass accepted candidates through the constitutional gate.
10. **Canary:** observe limited real use and roll back on policy-defined signals.
11. **Learn:** retain both accepted and rejected evidence for future mutation.

## Controls needed for causal claims

At minimum compare:

- parent phenotype + fixed model/environment;
- candidate phenotype + the same model/environment;
- parent and candidate on held-in tasks;
- parent and candidate on held-out tasks;
- repeated runs where stochasticity matters;
- cost and latency under identical budgets.

When a provider silently changes a hosted model, the result becomes lower-confidence unless a model fingerprint or contemporaneous control is available.

## Archive strategy

The archive keeps:

- Pareto-optimal candidates;
- behaviorally novel candidates;
- stepping stones that enable useful descendants;
- important failures and evaluator exploits;
- last-known-viable rollback points.

Parent selection balances exploitation and exploration. Diversity is measured at multiple levels: code diff, component graph, behavioral trace, failure signature, and evaluator outcome.

## Meta-evolution

Mutation operators and selection policies can become candidate-editable only after the base promotion system is stable. A meta-candidate is judged by **metaproductivity**:

```text
verified descendant frontier gain
---------------------------------
compute + time + human work + risk
```

A meta-candidate must be evaluated across multiple descendant-generation trials. A single lucky child does not prove a better improver.

## Stopping rules

An experiment stops when any occurs:

- budget or time ceiling;
- hard-constraint violation;
- no frontier gain over the configured patience window;
- evaluator integrity doubt;
- excessive uncertainty;
- human pause/revocation;
- duplicate work already represented in the archive.
