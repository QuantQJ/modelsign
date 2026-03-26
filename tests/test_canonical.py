"""Tests for canonical JSON serialization."""

from modelsign.identity.canonical import canonical_json


def test_sorted_keys():
    data = {"z": 1, "a": 2, "m": 3}
    result = canonical_json(data)
    assert result == b'{"a":2,"m":3,"z":1}'


def test_nested_sorted_keys():
    data = {"b": {"z": 1, "a": 2}, "a": 0}
    result = canonical_json(data)
    assert result == b'{"a":0,"b":{"a":2,"z":1}}'


def test_no_whitespace():
    data = {"key": "value", "num": 42}
    result = canonical_json(data)
    assert b" " not in result
    assert b"\n" not in result


def test_float_determinism():
    """Floats must serialize deterministically — primary risk is eval_metrics."""
    data = {"score": 0.87}
    result = canonical_json(data)
    assert canonical_json(data) == result


def test_float_edge_cases():
    """Edge cases that differ across platforms."""
    # Just verify determinism and no crashes — exact output depends on rfc8785
    for val in [0.0, 1.0, -0.0, 1e-10, 0.87]:
        result = canonical_json({"v": val})
        assert canonical_json({"v": val}) == result
        assert isinstance(result, bytes)


def test_large_integer():
    # rfc8785 enforces IEEE 754 safe integer domain (< 2^53 = 9007199254740992).
    # Values within the safe range serialize correctly.
    data = {"n": 9007199254740991}  # 2^53 - 1, max safe integer
    result = canonical_json(data)
    assert b"9007199254740991" in result


def test_large_integer_out_of_range():
    """rfc8785 raises IntegerDomainError for integers beyond IEEE 754 safe range."""
    import pytest
    from rfc8785._impl import IntegerDomainError
    with pytest.raises(IntegerDomainError):
        canonical_json({"n": 9999999999999999})


def test_unicode():
    data = {"emoji": "\U0001f600", "jp": "\u3042"}
    result = canonical_json(data)
    assert isinstance(result, bytes)
    import json
    parsed = json.loads(result)
    assert parsed == data


def test_empty_objects():
    assert canonical_json({}) == b"{}"
    assert canonical_json({"a": []}) == b'{"a":[]}'
    assert canonical_json({"a": {}}) == b'{"a":{}}'


def test_null_value():
    assert canonical_json({"a": None}) == b'{"a":null}'


def test_returns_bytes():
    result = canonical_json({"key": "value"})
    assert isinstance(result, bytes)


def test_idempotent():
    data = {"name": "test-model", "metrics": {"mmlu": 0.68, "humaneval": 0.53}}
    assert canonical_json(data) == canonical_json(data)
