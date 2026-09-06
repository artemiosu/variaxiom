#!/usr/bin/env bash
set -euo pipefail

REPO="artemiosu/variaxiom"
DESCRIPTION="Proof-gated evolution for AI agents. Agents mutate. Evidence decides."
TOPICS="ai-agents,agent-harness,self-improving-agents,agent-evaluation,ai-safety,capability-security,wasm,rust,python,open-source"

command -v gh >/dev/null || { echo "GitHub CLI (gh) is required." >&2; exit 1; }
gh auth status -h github.com >/dev/null

if ! gh repo view "$REPO" >/dev/null 2>&1; then
  gh repo create "$REPO" --public --description "$DESCRIPTION" --source=. --remote=origin
fi

gh repo edit "$REPO" \
  --description "$DESCRIPTION" \
  --homepage "https://artemiosu.github.io/variaxiom/" \
  --add-topic "$TOPICS" \
  --enable-issues \
  --enable-discussions \
  --enable-wiki=false \
  --delete-branch-on-merge \
  --enable-merge-commit=false \
  --enable-squash-merge \
  --enable-rebase-merge

while IFS='|' read -r name color description; do
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" --force
done <<'LABELS'
architecture|1d76db|Architecture and trust boundaries
idea|d4c5f9|Discussion-stage idea
needs-evidence|fbca04|Acceptance evidence is incomplete
proposal|c2e0c6|Bounded capability proposal
rfc|5319e7|Request for comments
triage|ededed|Needs maintainer triage
LABELS

echo "Core repository settings applied. Follow docs/project/github-setup.md for Pages,"
echo "security features, environments, and the founder-compatible main ruleset."
