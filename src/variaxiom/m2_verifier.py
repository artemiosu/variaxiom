"""Disabled M2.1 verification primitives.

This module only inspects bounded canonical wire bytes. It has no signing,
ambient trust, policy, activation, or lineage-append capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .canonical import JSONValue, canonical_json, sha256_bytes, strict_json_loads

MAX_M2_WIRE_BYTES: Final = 1_048_576


@dataclass(frozen=True, slots=True)
class M2WireRejection:
    """Stable fail-closed result for an invalid M2.1 wire representation."""

    stage: int
    code: str
    authorizing: bool = False


@dataclass(frozen=True, slots=True)
class CanonicalM2Wire:
    """Immutable canonical bytes accepted at the M2.1 stage-one boundary."""

    data: bytes
    sha256: str

    def decode(self) -> JSONValue:
        """Return a fresh decoded value so callers cannot mutate validated state."""

        value: JSONValue = strict_json_loads(self.data)
        return value


M2WireInspection = CanonicalM2Wire | M2WireRejection


def inspect_m2_wire(source: bytes | bytearray | memoryview) -> M2WireInspection:
    """Apply only the normative M2.1 stage-one wire checks.

    Success does not authenticate the payload and grants no authority. Later
    verifier stages must consume ``CanonicalM2Wire.data`` rather than a mutable
    object supplied by the caller.
    """

    source_size = source.nbytes if isinstance(source, memoryview) else len(source)
    if source_size > MAX_M2_WIRE_BYTES:
        return M2WireRejection(stage=1, code="input.limit_exceeded")
    data = bytes(source)

    try:
        value: JSONValue = strict_json_loads(data)
    except (TypeError, ValueError) as error:
        message = str(error)
        if "duplicate JSON object key" in message:
            code = "input.duplicate_member"
        elif "nesting exceeds" in message:
            code = "input.limit_exceeded"
        else:
            code = "input.encoding_invalid"
        return M2WireRejection(stage=1, code=code)

    if canonical_json(value) != data:
        return M2WireRejection(stage=1, code="input.encoding_invalid")

    return CanonicalM2Wire(data=data, sha256=sha256_bytes(data))
