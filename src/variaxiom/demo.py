"""Runnable proof-gated evolution demonstration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .canonical import JSONValue
from .constitution import Constitution
from .domain import Candidate, Evidence, PromotionDecision
from .evaluation import evaluate_slug_tool
from .promotion import PromotionContext, PromotionGate
from .render import render_demo_report
from .workspace import Workspace

GENESIS_ID = "genome:genesis-v0"


@dataclass(slots=True)
class _DemoClock:
    """A deterministic clock so independent demo runs produce the same ledger head."""

    current: datetime = datetime(2026, 9, 6, 13, 0, tzinfo=UTC)

    def next(self) -> str:
        value = self.current.isoformat()
        self.current += timedelta(seconds=1)
        return value


def _record_candidate(
    workspace: Workspace,
    candidate: Candidate,
    clock: _DemoClock,
) -> None:
    workspace.ledger.append(
        kind="candidate.proposed",
        actor=candidate.proposer,
        payload=candidate.as_dict(),
        timestamp=clock.next(),
    )


def _record_evidence(
    workspace: Workspace,
    evidence: list[Evidence],
    clock: _DemoClock,
) -> None:
    for item in evidence:
        workspace.write_json(f"evidence/{item.evidence_id.replace(':', '_')}.json", item.as_dict())
        workspace.ledger.append(
            kind="evidence.recorded",
            actor=item.verifier,
            payload=item.as_dict(),
            timestamp=clock.next(),
        )


def _record_decision(
    workspace: Workspace,
    decision: PromotionDecision,
    clock: _DemoClock,
) -> None:
    workspace.write_json(
        f"promotions/{decision.candidate_id.replace(':', '_')}.json",
        decision.as_dict(),
    )
    workspace.ledger.append(
        kind="promotion.decided",
        actor="kernel:promotion-gate",
        payload=decision.as_dict(),
        timestamp=clock.next(),
    )
    if decision.accepted:
        workspace.ledger.append(
            kind="genome.promoted",
            actor="kernel:promotion-gate",
            payload={
                "candidate_id": decision.candidate_id,
                "decision_hash": decision.fingerprint,
            },
            timestamp=clock.next(),
        )


def run_demo(root: Path, *, reset: bool = False) -> dict[str, JSONValue]:
    """Run the deterministic Authority Test fixture in ``root``."""

    workspace = Workspace.reset(root) if reset else Workspace.open(root)
    clock = _DemoClock()

    genesis_artifact = {
        "kind": "genome",
        "id": GENESIS_ID,
        "capabilities": ["artifact.read", "artifact.write", "evaluation.request"],
        "description": "Minimal trusted seed for the reference demonstration.",
    }
    genesis_hash = workspace.artifacts.put_json(genesis_artifact)
    workspace.ledger.append(
        kind="system.genesis",
        actor="owner:artemiosu",
        payload={"genome_id": GENESIS_ID, "artifact_hash": genesis_hash},
        timestamp=clock.next(),
    )

    tool_artifact = {
        "kind": "tool-package",
        "name": "slug-normalizer",
        "version": "1.0.0-candidate",
        "interface": {"input": "string", "output": "string"},
        "implementation": {
            "kind": "bootstrap-trusted-demo",
            "algorithm": "unicode-ascii-slug-v1",
        },
        "claim": "Normalize human-readable text into a stable ASCII slug.",
    }
    tool_hash = workspace.artifacts.put_json(tool_artifact)

    baseline_caps = frozenset({"artifact.read", "artifact.write", "evaluation.request"})
    unsafe = Candidate(
        candidate_id="candidate:slug-tool-unbounded",
        parent_id=GENESIS_ID,
        artifact_hash=tool_hash,
        proposer="agent:mutator-1",
        rollback_target=GENESIS_ID,
        baseline_capabilities=baseline_caps,
        requested_capabilities=baseline_caps | {"network.unrestricted"},
        estimated_cost_micro_usd=30_000,
        metadata={"hypothesis": "The tool needs unrestricted network access."},
    )
    safe = Candidate(
        candidate_id="candidate:slug-tool-bounded",
        parent_id=GENESIS_ID,
        artifact_hash=tool_hash,
        proposer="agent:mutator-1",
        rollback_target=GENESIS_ID,
        baseline_capabilities=baseline_caps,
        requested_capabilities=baseline_caps,
        estimated_cost_micro_usd=30_000,
        metadata={"hypothesis": "The tool can run without new authority."},
    )

    context = PromotionContext(
        known_lineage_ids=frozenset({GENESIS_ID}),
        known_artifact_hashes=frozenset({genesis_hash, tool_hash}),
        lineage_capabilities={GENESIS_ID: baseline_caps},
    )
    gate = PromotionGate(Constitution.default())

    decisions: list[PromotionDecision] = []
    for candidate in (unsafe, safe):
        _record_candidate(workspace, candidate, clock)
        evidence = evaluate_slug_tool(candidate)
        _record_evidence(workspace, evidence, clock)
        decision = gate.decide(candidate, evidence, context)
        _record_decision(workspace, decision, clock)
        decisions.append(decision)

    verification = workspace.ledger.verify()
    report: dict[str, JSONValue] = {
        "project": "Variaxiom",
        "tagline": "Agents mutate. Evidence decides.",
        "fixture": "authority-test/v1",
        "reproducibility": "deterministic timestamps and canonical JSON",
        "workspace": str(root),
        "artifact_hash": tool_hash,
        "decisions": [decision.as_dict() for decision in decisions],
        "ledger": {
            "valid": verification.valid,
            "event_count": verification.event_count,
            "head_hash": verification.head_hash,
            "errors": list(verification.errors),
        },
        "lesson": (
            "Passing tests does not grant authority. The unbounded candidate is rejected; "
            "the capability-bounded candidate is promoted."
        ),
    }
    workspace.write_json("reports/demo-report.json", report)
    render_demo_report(report, workspace.root / "reports" / "authority-test.html")
    return report
