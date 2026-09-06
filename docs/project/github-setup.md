# GitHub publication and repository settings

This checklist records and maintains the public repository `artemiosu/variaxiom`. The initial
repository, `main` push, Discussions, Pages, security automation, topics, and founder-compatible
branch protection were applied on 2026-09-06. Treat GitHub settings as external state and verify
them again before claiming they remain enabled.

## 1. Create and push (completed)

The local repository tracks the HTTPS remote because SSH key authentication was unavailable:

```bash
git push -u origin main
```

Do not use GitHub's “initialize with README/license” options because those files already exist locally.

## 2. Repository description

```text
Proof-gated evolution for AI agents. Agents mutate. Evidence decides.
```

## 3. Topics

Use a focused set rather than keyword stuffing:

```text
ai-agents
agent-harness
self-improving-agents
agent-evaluation
ai-safety
capability-security
wasm
rust
python
open-source
```

## 4. Visual and social metadata

- upload `assets/social-preview.png` as the social preview;
- keep the wordmark in the README;
- keep Discussions enabled and maintain its initial categories;
- keep the live Pages site linked from the repository website field;
- enable Releases when the first tagged release is ready.

## 5. General settings

Enable:

- Issues;
- Discussions;
- Projects only when there is a real public board;
- Preserve this repository;
- Automatically delete head branches after merge;
- Web-based commit signoff if available;
- vulnerability reporting / private security advisories;
- dependency graph, Dependabot alerts and security updates;
- secret scanning and push protection where available.

Disable initially:

- Wikis, to avoid a second documentation source;
- merge commits, unless a contributor workflow requires them;
- packages until a publishable package exists.

Recommended merge policy:

- allow squash merge;
- optionally allow rebase merge;
- require a meaningful PR title because squash titles become history.

## 6. Ruleset for `main`

Create a branch ruleset with:

- pull request required;
- at least one approving review; increase to two for `kernel/`, `constitution/`, `schemas/`, and evaluator policy once multiple maintainers exist;
- dismiss stale approvals after new commits;
- require conversation resolution;
- require signed commits when operationally feasible;
- block force pushes and deletion;
- require status checks:
  - Required checks;
  - dependency-review;
- require linear history;
- do not allow administrator bypass for security-critical changes except a documented break-glass path.

At repository birth, one-person maintenance makes mandatory external review impossible. Use a temporary founder exception, record it publicly, and remove it after the second trusted maintainer is appointed.

## 7. Environments

Create protected environments before publishing packages or docs:

- `github-pages`;
- `release`;
- later `pypi` and `crates-io`.

Use trusted publishing/OIDC rather than long-lived publication tokens.

## 8. GitHub Pages

The static site was observed live on 2026-09-06. It lives in `docs/` and requires no build
system. Treat these settings as external state and recheck them after repository-rule changes.

- Pages source: deploy from branch;
- branch: `main`;
- folder: `/docs`.

The generated Authority Test is at `docs/demo/authority-test.html`.

## 9. Discussions layout

Recommended categories:

- `Announcements` — maintainer-only release and Trial posts;
- `Ideas / RFC preflight`;
- `Research replications`;
- `Show and tell`;
- `Q&A`.

Do not open a Discord immediately. GitHub Discussions preserves searchable technical context and reduces community fragmentation. Add synchronous chat only after persistent demand.

## 10. First public issues

Create only the curated issues in [`../launch/initial-issues.ru.md`](../launch/initial-issues.ru.md). Each issue needs:

- bounded outcome;
- explicit non-goals;
- test/evidence requirement;
- architecture owner;
- estimated review surface;
- label and difficulty.

## 11. Release sequence

1. Push privately or as a public draft repository.
2. Run CI and security workflows.
3. Fix every broken README path and one-command demo issue.
4. Ask 3–5 technically strong reviewers to reproduce the proof without a call.
5. Publish `v0.1.0-alpha.1` with a signed/attested artifact when available.
6. Launch only after at least two independent clean reproductions.

## 12. Namespace follow-up

The name check in [`naming-clearance.md`](naming-clearance.md) is preliminary. Reserve relevant package/social/domain namespaces before a coordinated launch and obtain professional trademark review before material commercial investment.
