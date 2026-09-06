from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from variaxiom.canonical import canonical_json
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
            path.write_bytes(canonical_json(event) + b"\n")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertIn("event hash mismatch", " ".join(result.errors))

    def test_jsonl_framing_preserves_valid_unicode_scalars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = HashChainLedger(path)
            text = "next-line:\u0085 separator:\u2028 paragraph:\u2029"
            ledger.append(kind="unicode", actor="tester", payload={"text": text})
            self.assertEqual(path.read_bytes().count(b"\n"), 1)
            self.assertEqual(ledger.events()[0]["payload"]["text"], text)
            self.assertTrue(ledger.verify().valid)

    def test_refuses_to_extend_a_corrupt_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = HashChainLedger(path)
            ledger.append(kind="one", actor="tester", payload={"value": 1})
            event = json.loads(path.read_text("utf-8"))
            event["payload"]["value"] = 999
            path.write_bytes(canonical_json(event) + b"\n")
            with self.assertRaises(RuntimeError):
                ledger.append(kind="two", actor="tester", payload={"value": 2})


if __name__ == "__main__":
    unittest.main()
