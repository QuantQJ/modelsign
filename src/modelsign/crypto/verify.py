"""Ed25519 verification operations."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_bytes(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
