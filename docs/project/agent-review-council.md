# Independent agent-review council

This process is a defense-in-depth substitute when an external human reviewer is unavailable. It
must never be described as human, organizationally independent, or proof that a design is secure.

## Required panel

Promotion-sensitive specifications receive three isolated, read-only reviews before acceptance:

1. cryptographic protocol and misuse-resistance;
2. authority/capability threat modelling and adversarial scenarios;
3. wire-contract, cross-runtime conformance, reproducibility, and resource bounds.

Each reviewer receives the same immutable commit and a distinct written mandate. Reviewers do not
edit the branch or coordinate before submitting their initial verdicts. The synthesis records every
P0–P2 finding, disagreements, exact remediation, residual risk, and the reviewed commits.

## Gate

- Any P0 or P1 blocks acceptance and implementation.
- P2 must be fixed or explicitly deferred with a bounded reason and acceptance test.
- After changes, all three reviewers re-review only the frozen delta plus affected context.
- Acceptance requires three PASS verdicts, green repository verification, and a published report.
- A GitHub review bot may add a fourth signal but cannot satisfy the panel or override a blocker.
- Implementation is reviewed again after schemas/vectors and before enabling cryptographic code.

The founder may coordinate the process but cannot erase findings or count as an independent vote.

## Durable evidence

The report under `docs/reports/` records reviewer type, prompts/mandates, commit hashes, findings,
remediation mapping, checks, and final verdict. GitHub issue and PR comments link the report. Any
later change to normative signed bytes, trust anchors, roles, schemas, or verification order reopens
the gate.
