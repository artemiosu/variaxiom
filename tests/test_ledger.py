from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from variaxiom.ledger import HashChainLedger


class LedgerTests(unittest.TestCase):
    def test_valid_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = HashChainLedger(Path(directory) / "ledger.jsonl")
            ledger.append(kind="one", actor="tester", payload={"value": 1})
            ledger.append(kind="two", actor="tester", payload={"value": 2})
            result = ledger.verify()
            self.assertTrue(result.valid)
            self.assertEqual(result.event_count, 2)

    def test_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = HashChainLedger(path)
            ledger.append(kind="one", actor="tester", payload={"value": 1})
            event = json.loads(path.read_text("utf-8"))
            event["payload"]["value"] = 999
            path.write_text(json.dumps(event) + "\n", "utf-8")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertIn("event hash mismatch", " ".join(result.errors))


if __name__ == "__main__":
    unittest.main()
