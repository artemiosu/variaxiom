"""Content-addressed artifact storage."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_bytes


class ArtifactStore:
    """A minimal immutable SHA-256 artifact store.

    The store never overwrites a digest with different bytes. Content address
    and bytes are rechecked on reads, so silent mutation is detectable.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("Artifact digest must be a lowercase SHA-256 hex string")
        return self.root / "sha256" / digest[:2] / digest[2:]

    def put_bytes(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        destination = self.path_for(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            existing = destination.read_bytes()
            if existing != data:
                raise RuntimeError(f"Digest collision or artifact corruption: {digest}")
            return digest

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{digest}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if destination.read_bytes() != data:
                    raise RuntimeError(f"Artifact changed during concurrent write: {digest}")
            finally:
                temporary.unlink(missing_ok=True)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return digest

    def put_json(self, value: Any) -> str:
        return self.put_bytes(canonical_json(value) + b"\n")

    def get_bytes(self, digest: str) -> bytes:
        data = self.path_for(digest).read_bytes()
        actual = sha256_bytes(data)
        if actual != digest:
            raise RuntimeError(f"Artifact integrity failure: expected {digest}, found {actual}")
        return data

    def contains(self, digest: str) -> bool:
        path = self.path_for(digest)
        if not path.is_file():
            return False
        return sha256_bytes(path.read_bytes()) == digest
