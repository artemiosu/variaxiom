from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from variaxiom.demo import run_demo


class DemoTests(unittest.TestCase):
    def test_demo_rejects_escalation_and_promotes_bounded_variant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_demo(Path(directory), reset=True)
            decisions = report["decisions"]
            self.assertEqual(decisions[0]["status"], "rejected")
            self.assertEqual(decisions[1]["status"], "accepted")
            self.assertTrue(report["ledger"]["valid"])
            html = Path(directory) / "reports" / "authority-test.html"
            self.assertTrue(html.is_file())
            rendered = html.read_text("utf-8")
            self.assertIn("Agents mutate.", rendered)
            self.assertIn("PROMOTED", rendered)
            self.assertIn("REJECTED", rendered)

    def test_demo_ledger_is_reproducible_across_clean_workspaces(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            report_a = run_demo(Path(first), reset=True)
            report_b = run_demo(Path(second), reset=True)
            self.assertEqual(
                report_a["ledger"]["head_hash"],
                report_b["ledger"]["head_hash"],
            )
            self.assertEqual(report_a["artifact_hash"], report_b["artifact_hash"])


if __name__ == "__main__":
    unittest.main()
