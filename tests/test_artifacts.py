from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from variaxiom.artifacts import ArtifactStore


class ArtifactStoreTests(unittest.TestCase):
    def test_round_trip_and_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(Path(directory))
            first = store.put_bytes(b"evidence")
            second = store.put_bytes(b"evidence")
            self.assertEqual(first, second)
            self.assertEqual(store.get_bytes(first), b"evidence")
            self.assertTrue(store.contains(first))

    def test_rejects_invalid_digest_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(Path(directory))
            with self.assertRaises(ValueError):
                store.path_for("not-a-digest")


if __name__ == "__main__":
    unittest.main()
