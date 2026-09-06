#!/usr/bin/env python3
"""Regenerate deterministic, publishable demo artifacts under docs/demo/."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))

from variaxiom.demo import run_demo  # noqa: E402
from variaxiom.render import render_demo_report  # noqa: E402

GENERATED_FILES = ("authority-test.html", "demo-report.json", "lineage.jsonl")


def generate(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="variaxiom-docs-") as temporary:
        workspace = Path(temporary) / "runtime"
        report = run_demo(workspace, reset=True)
        report["workspace"] = ".variaxiom"

        report_path = destination / "demo-report.json"
        report_path.write_bytes(
            (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
        )
        render_demo_report(report, destination / "authority-test.html")
        shutil.copyfile(workspace / "lineage.ledger.jsonl", destination / "lineage.jsonl")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "docs" / "demo"

    if args.check:
        with tempfile.TemporaryDirectory(prefix="variaxiom-docs-check-") as temporary:
            generated = Path(temporary) / "generated"
            generate(generated)
            stale = [
                name
                for name in GENERATED_FILES
                if not (destination / name).is_file()
                or (destination / name).read_bytes() != (generated / name).read_bytes()
            ]
        if stale:
            print("Stale generated demo artifacts: " + ", ".join(stale), file=sys.stderr)
            print("Run scripts/regenerate_demo_docs.py and review the diff.", file=sys.stderr)
            return 1
        print("Generated public demo artifacts are current.")
        return 0

    generate(destination)
    print(f"Generated public demo artifacts in {destination.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
