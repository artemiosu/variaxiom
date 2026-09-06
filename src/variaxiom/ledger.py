"""Append-only, hash-chained lineage ledger."""

from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .canonical import JSONValue, canonical_json, content_hash, strict_json_loads, to_json_value

GENESIS_HASH = "0" * 64

try:  # pragma: no cover - Windows fallback is intentionally simple.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    valid: bool
    event_count: int
    head_hash: str
    errors: tuple[str, ...] = ()


@contextmanager
def _exclusive_lock(handle: Any) -> Generator[None]:
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class HashChainLedger:
    """A compact local audit ledger.

    This is an integrity-evident log, not a Byzantine consensus protocol. The
    production architecture adds signatures, remote witnesses, and object-store
    retention; the bootstrap keeps the semantics inspectable.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        kind: str,
        actor: str,
        payload: dict[str, JSONValue],
        timestamp: str | None = None,
    ) -> dict[str, JSONValue]:
        if not kind or not actor:
            raise ValueError("Ledger event kind and actor must be non-empty")

        self.path.touch(exist_ok=True)
        with self.path.open("a+b") as handle, _exclusive_lock(handle):
            handle.seek(0)
            existing = self._parse_events(handle.read())
            verification = self._verify_events(existing)
            if not verification.valid:
                raise RuntimeError(
                    "Refusing to append to an invalid ledger: " + "; ".join(verification.errors)
                )
            previous_hash = verification.head_hash
            sequence = verification.event_count

            body: dict[str, JSONValue] = {
                "sequence": sequence,
                "timestamp": timestamp or datetime.now(UTC).isoformat(),
                "kind": kind,
                "actor": actor,
                "payload": to_json_value(payload),
                "previous_hash": previous_hash,
            }
            event = {**body, "hash": content_hash(body)}
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            return event

    def events(self) -> list[dict[str, JSONValue]]:
        if not self.path.exists():
            return []
        return self._parse_events(self.path.read_bytes())

    @staticmethod
    def _parse_events(data: bytes) -> list[dict[str, JSONValue]]:
        if not data:
            return []
        if not data.endswith(b"\n"):
            raise ValueError("Ledger is missing its final LF record separator")
        records = data.split(b"\n")[:-1]
        events: list[dict[str, JSONValue]] = []
        for line_number, line in enumerate(records, 1):
            if not line:
                raise ValueError(f"Empty ledger record at line {line_number}")
            try:
                value = strict_json_loads(line)
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid ledger JSON at line {line_number}: {error}") from error
            if not isinstance(value, dict):
                raise ValueError(f"Ledger event at line {line_number} is not an object")
            if canonical_json(value) != line:
                raise ValueError(f"Ledger event at line {line_number} is not canonical JSON")
            events.append(cast(dict[str, JSONValue], value))
        return events

    @staticmethod
    def _verify_events(events: list[dict[str, JSONValue]]) -> LedgerVerification:
        errors: list[str] = []
        previous_hash = GENESIS_HASH
        head = GENESIS_HASH
        for expected_sequence, event in enumerate(events):
            index = expected_sequence + 1
            actual_sequence = event.get("sequence")
            if actual_sequence != expected_sequence:
                errors.append(
                    f"line {index}: sequence {actual_sequence!r}, expected {expected_sequence}"
                )
            if event.get("previous_hash") != previous_hash:
                errors.append(f"line {index}: previous hash does not match chain head")

            supplied_hash = event.get("hash")
            body = {key: value for key, value in event.items() if key != "hash"}
            calculated_hash = content_hash(body)
            if supplied_hash != calculated_hash:
                errors.append(f"line {index}: event hash mismatch")

            if isinstance(supplied_hash, str):
                previous_hash = supplied_hash
                head = supplied_hash
        return LedgerVerification(not errors, len(events), head, tuple(errors))

    def verify(self) -> LedgerVerification:
        try:
            events = self.events()
        except (TypeError, ValueError) as error:
            return LedgerVerification(False, 0, GENESIS_HASH, (str(error),))
        return self._verify_events(events)
