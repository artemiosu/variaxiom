"""Workspace assembly and integrity inspection."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .artifacts import ArtifactStore
from .canonical import JSONValue
from .ledger import HashChainLedger


@dataclass(frozen=True, slots=True)
class Workspace:
    root: Path
    artifacts: ArtifactStore
    ledger: HashChainLedger

    @classmethod
    def open(cls, root: Path, *, create: bool = True) -> "Workspace":
        if create:
            root.mkdir(parents=True, exist_ok=True)
            for name in ("artifacts", "evidence", "promotions", "reports"):
                (root / name).mkdir(parents=True, exist_ok=True)
        return cls(
            root=root,
            artifacts=ArtifactStore(root / "artifacts"),
            ledger=HashChainLedger(root / "lineage.ledger.jsonl"),
        )

    @classmethod
    def reset(cls, root: Path) -> "Workspace":
        if root.exists():
            shutil.rmtree(root)
        return cls.open(root)

    def write_json(self, relative_path: str, value: dict[str, JSONValue]) -> Path:
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination
