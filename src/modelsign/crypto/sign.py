"""Ed25519 signing operations with domain-prefixed messages."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sign_bytes(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign a message with Ed25519. Returns 64-byte signature."""
    return private_key.sign(message)


def build_file_message(file_hash: str, identity_bytes: bytes) -> bytes:
    """Build the message to sign for a single file.

    Format: b"modelsign-v1:" + file_hash + b":" + identity_bytes

    file_hash is always 64 hex chars (SHA-256), so the colon separator
    is unambiguous. Do not change this invariant without updating the
    domain prefix version.
    """
    return b"modelsign-v1:" + file_hash.encode("utf-8") + b":" + identity_bytes


def build_dir_message(manifest_hash: str, identity_bytes: bytes) -> bytes:
    """Build the message to sign for a directory.

    Format: b"modelsign-v1:dir:" + manifest_hash + b":" + identity_bytes
    """
    return b"modelsign-v1:dir:" + manifest_hash.encode("utf-8") + b":" + identity_bytes


def _length_prefixed(name: str) -> bytes:
    """Encode a name so it cannot be confused with what follows it.

    The length prefix is what keeps a name containing ":" from shifting the
    field boundaries — the same reason DSSE's pre-authentication encoding
    prefixes lengths rather than relying on separators alone.
    """
    raw = name.encode("utf-8")
    return str(len(raw)).encode("ascii") + b":" + raw


def build_file_message_v2(name: str, file_hash: str, identity_bytes: bytes) -> bytes:
    """Message to sign for a single file, with its name authenticated.

    Format: b"modelsign-v2:file:" + len(name) + b":" + name + b":"
            + file_hash + b":" + identity_bytes

    v1 left the name out, so a .sig's `file` field was unauthenticated and
    two signed files could be presented under each other's names.
    """
    return (
        b"modelsign-v2:file:"
        + _length_prefixed(name)
        + b":"
        + file_hash.encode("utf-8")
        + b":"
        + identity_bytes
    )

