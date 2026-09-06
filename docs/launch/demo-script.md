# Demo Script: The Authority Test

Target length: 60–90 seconds.

## Scene 1 — claim

On screen:

```text
An agent changed itself.
The tests passed.
Should the change survive?
```

Narration:

> Most self-improving agents stop at “the new version passed.” Variaxiom asks a second question: what changed in its authority, lineage, and evidence?

## Scene 2 — run

```bash
bash scripts/demo.sh
```

Show two candidate IDs.

## Scene 3 — surprise

Highlight:

```text
candidate:slug-tool-unbounded → REJECTED
reason: requests authority not covered by an explicit external grant
```

Narration:

> It works, but it silently asks for unrestricted network access. Functional success does not grant authority.

## Scene 4 — accepted descendant

Highlight:

```text
candidate:slug-tool-bounded → ACCEPTED
all constitutional promotion gates passed
```

## Scene 5 — lineage

Show event ledger and report hash.

Narration:

> Both candidates and all evidence remain in a tamper-evident lineage. The rejected mutation becomes knowledge; the bounded mutation becomes inheritable.

## End card

```text
VARIAXIOM
Agents mutate. Evidence decides.
github.com/artemiosu/variaxiom
```
