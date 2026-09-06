"""Canonical serialization and hashing utilities."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes.

    Floats with NaN or infinity are rejected because they are not portable JSON
    values and would make evidence hashes ambiguous across implementations.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def content_hash(value: Any) -> str:
    """Hash a JSON-compatible value using canonical serialization."""

    return sha256_bytes(canonical_json(value))


def to_json_value(value: Any) -> JSONValue:
    """Convert common immutable Python structures into JSON-compatible values."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): to_json_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return [to_json_value(item) for item in sorted(value, key=str)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_json_value(item) for item in value]
    raise TypeError(f"Unsupported value for canonical JSON: {type(value).__name__}")
