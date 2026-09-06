# Governance

Variaxiom starts as a founder-led open-source project with evidence-based decision making and an explicit path toward broader stewardship.

## Roles

### Founder and initial steward

The repository owner, `artemiosu`, sets the initial direction, manages releases, resolves deadlocks, and protects the constitution during the bootstrap phase.

### Maintainers

Maintainers may triage issues, review and merge changes, lead working groups, and cut releases within their delegated scope. Maintainer status is earned through sustained high-quality work, sound judgment, respectful collaboration, and attention to security—not by star count or promotional reach.

### Constitutional reviewers

A small set of reviewers independently approves changes to invariants, promotion logic, authority policy, hidden-evaluator governance, and the trusted kernel. The author of a change cannot satisfy all required reviews.

### Contributors

Anyone may propose code, research, evaluations, documentation, or experiments under the contribution rules.

## Decision classes

| Class | Examples | Process |
|---|---|---|
| Routine | docs, tests, small fixes | maintainer review |
| Architectural | protocol, new dependency, component boundary | public ADR/RFC + review |
| Constitutional | authority, promotion, governance, evaluator control | RFC + two independent constitutional reviews + founder/steward approval |
| Emergency | active vulnerability or integrity failure | temporary steward action, then public postmortem/RFC |

## Principles

- Evidence can overturn seniority.
- Security-sensitive checks cannot be weakened silently.
- Rejected experiments remain useful historical evidence.
- Decisions record assumptions, alternatives, and reversal conditions.
- Project governance and agent governance are separate: maintainers govern software; the software enforces bounded agent evolution.

## Becoming a maintainer

A contributor may be nominated after a visible body of work. Existing maintainers evaluate technical depth, review quality, reliability, communication, and stewardship behavior. Scope can begin narrowly and expand. Inactivity is not misconduct; access may be reduced after a documented dormant period for security hygiene.

## Amendments

Changes to this document require a governance RFC. Changes to the machine-readable constitution additionally follow its amendment rules: independent review, steward approval, a migration dry run, and a rollback plan.
