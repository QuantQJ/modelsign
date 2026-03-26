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
