"""Command-line interface for the Variaxiom reference laboratory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .demo import run_demo
from .workspace import Workspace


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="variaxiom",
        description="Proof-gated evolutionary substrate for AI agents.",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=Path(".variaxiom"),
        help="runtime workspace (default: .variaxiom)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run the bounded promotion demonstration")
    demo.add_argument("--reset", action="store_true", help="replace existing demo state")

    subparsers.add_parser("verify", help="verify the hash-chained lineage ledger")
    subparsers.add_parser("status", help="show workspace status")
    subparsers.add_parser("init", help="initialize an empty workspace")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    home: Path = args.home

    if args.command == "demo":
        report = run_demo(home, reset=bool(args.reset))
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if bool(report["ledger"]["valid"]) else 1  # type: ignore[index]

    workspace = Workspace.open(home)
    if args.command == "init":
        print(f"Initialized Variaxiom workspace at {workspace.root}")
        return 0

    verification = workspace.ledger.verify()
    if args.command == "verify":
        print(
            json.dumps(
                {
                    "valid": verification.valid,
                    "event_count": verification.event_count,
                    "head_hash": verification.head_hash,
                    "errors": verification.errors,
                },
                indent=2,
            )
        )
        return 0 if verification.valid else 1

    if args.command == "status":
        print(
            json.dumps(
                {
                    "workspace": str(workspace.root),
                    "ledger_exists": workspace.ledger.path.exists(),
                    "ledger_valid": verification.valid,
                    "event_count": verification.event_count,
                    "head_hash": verification.head_hash,
                },
                indent=2,
            )
        )
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
