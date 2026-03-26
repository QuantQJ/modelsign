"""Deterministic JSON serialization using RFC 8785 (JCS).

This module is the SINGLE SOURCE OF TRUTH for JSON canonicalization
in modelsign. All signing and verification MUST use canonical_json()
from this module to produce deterministic bytes.
"""

import rfc8785


def canonical_json(obj: dict) -> bytes:
    """Serialize a dict to canonical JSON bytes (RFC 8785 JCS).

    Returns UTF-8 bytes with:
    - Keys sorted lexicographically at all nesting levels
    - No extra whitespace
    - ECMAScript number serialization
    - Minimal string escaping
    """
    return rfc8785.dumps(obj)
