"""Ed25519 key generation, loading, fingerprints, and keyring management."""

import hashlib
import os
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Display-only fingerprint length. 8 hex chars = 32 bits.
# NOT collision-resistant. Use full public key bytes for registry lookups (v2).
FINGERPRINT_HEX_CHARS = 8


def generate_keypair(key_dir: Path) -> tuple[Path, Path]:
    """Generate Ed25519 keypair. Returns (priv_path, pub_path).

    If keys already exist, returns existing paths without overwriting.
    """
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / "private.pem"
    pub_path = key_dir / "public.pem"

    if priv_path.exists() and pub_path.exists():
        return priv_path, pub_path

    private_key = Ed25519PrivateKey.generate()

    priv_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(priv_path, 0o600)

    pub_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    return priv_path, pub_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def public_key_to_bytes(key: Ed25519PublicKey) -> bytes:
    """Extract raw 32-byte public key."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def compute_fingerprint(key: Ed25519PublicKey) -> str:
    """Compute display fingerprint: ed25519:<first 8 hex of SHA-256(raw_pubkey)>.

    This is display-only (32 bits), NOT collision-resistant.
    """
    raw = public_key_to_bytes(key)
    digest = hashlib.sha256(raw).hexdigest()
    return f"ed25519:{digest[:FINGERPRINT_HEX_CHARS]}"


def keyring_add(keyring_dir: Path, pubkey_path: Path, alias: str) -> None:
    """Add a public key to the trusted keyring."""
    keyring_dir = Path(keyring_dir)
    keyring_dir.mkdir(parents=True, exist_ok=True)
    dest = keyring_dir / f"{alias}.pem"
    shutil.copy2(pubkey_path, dest)


def keyring_list(keyring_dir: Path) -> list[dict]:
    """List all trusted keys with alias and fingerprint."""
    keyring_dir = Path(keyring_dir)
    if not keyring_dir.exists():
        return []
    result = []
    for pem_file in sorted(keyring_dir.glob("*.pem")):
        key = load_public_key(pem_file)
        result.append({
            "alias": pem_file.stem,
            "fingerprint": compute_fingerprint(key),
            "path": str(pem_file),
        })
    return result


def keyring_remove(keyring_dir: Path, alias: str) -> None:
    """Remove a key from the trusted keyring by alias."""
    target = Path(keyring_dir) / f"{alias}.pem"
    if target.exists():
        target.unlink()
