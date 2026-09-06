"""Canonical serialization and hashing utilities."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, cast

JSONScalar = str | int | bool | None
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

MAX_SAFE_INTEGER = (1 << 53) - 1
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER
MAX_CANONICAL_DEPTH = 64


def _validate_canonical_value(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError(f"canonical v1 nesting exceeds {MAX_CANONICAL_DEPTH} at {path}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError(f"lone Unicode surrogate is forbidden at {path}")
        return
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"integer outside canonical v1 range at {path}")
        return
    if isinstance(value, float):
        raise TypeError(f"floating-point values are forbidden in canonical v1 JSON at {path}")
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            if not isinstance(key, str):
                raise TypeError(f"canonical v1 object key is not a string at {path}")
            _validate_canonical_value(key, f"{path}.<key>", depth)
            _validate_canonical_value(item, f"{path}.{key}", depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], value)
        for index, item in enumerate(sequence):
            _validate_canonical_value(item, f"{path}[{index}]", depth + 1)
        return
    raise TypeError(f"unsupported canonical v1 value at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes.

    The v1 profile rejects all floats and integers outside the interoperable
    IEEE-754 exact-integer range. See the active conformance specification.
    """

    _validate_canonical_value(value)
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


def strict_json_loads(source: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate keys and non-standard constants."""

    if isinstance(source, (bytes, bytearray)):
        try:
            source = bytes(source).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("canonical JSON input must be UTF-8") from error
    if source.startswith("\ufeff"):
        raise ValueError("canonical JSON input cannot contain a BOM")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    value = json.loads(
        source,
        object_pairs_hook=object_from_pairs,
        parse_constant=reject_constant,
    )
    _validate_canonical_value(value)
    return value


def to_json_value(value: Any) -> JSONValue:
    """Convert common immutable Python structures into JSON-compatible values."""

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        _validate_canonical_value(value)
        return value
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("integer outside canonical v1 range")
        return value
    if isinstance(value, float):
        raise TypeError("floating-point values are forbidden in canonical v1 JSON")
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        if not all(isinstance(key, str) for key in mapping):
            raise TypeError("canonical v1 object keys must be strings")
        string_mapping = cast(Mapping[str, object], mapping)
        return {key: to_json_value(item) for key, item in string_mapping.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], value)
        return [to_json_value(item) for item in sequence]
    raise TypeError(f"Unsupported value for canonical JSON: {type(value).__name__}")
