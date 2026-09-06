#!/usr/bin/env python3
"""Regenerate deterministic, publishable demo artifacts under docs/demo/."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

import sys

sys.path.insert(0, str(SRC))

from variaxiom.demo import run_demo  # noqa: E402
from variaxiom.render import render_demo_report  # noqa: E402


def main() -> int:
    destination = ROOT / "docs" / "demo"
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="variaxiom-docs-") as temporary:
        workspace = Path(temporary) / "runtime"
        report = run_demo(workspace, reset=True)
        report["workspace"] = ".variaxiom"

        report_path = destination / "demo-report.json"
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        render_demo_report(report, destination / "authority-test.html")
        shutil.copyfile(workspace / "lineage.ledger.jsonl", destination / "lineage.jsonl")

    print(f"Generated public demo artifacts in {destination.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
