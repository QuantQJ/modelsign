"""Library API for signing and verifying models.

The CLI is a thin wrapper over these functions. Load hooks, CI jobs and
serving code call them directly instead of shelling out.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from modelsign.crypto.keys import (
    compute_fingerprint,
    keyring_list,
    load_private_key,
    load_public_key,
    public_key_to_bytes,
)
from modelsign.crypto.sign import build_dir_message, build_file_message, sign_bytes
from modelsign.crypto.verify import verify_bytes
from modelsign.formats.directory import hash_directory
from modelsign.formats.single import hash_file
from modelsign.identity.canonical import canonical_json
from modelsign.identity.card import ModelCard, validate_card
from modelsign.sig import SigFile, read_sig, write_sig

DEFAULT_KEY_DIR = Path.home() / ".modelsign"

#: Identity was checked against a key supplied by the caller.
TRUST_PUBKEY = "pubkey"
#: Identity was checked against a key already in the local keyring.
TRUST_KEYRING = "keyring"
#: Only the signature's own embedded key was available. Proves the bytes
#: are unchanged since signing; proves nothing about who signed them.
TRUST_EMBEDDED = "embedded"

_TRUSTED = (TRUST_PUBKEY, TRUST_KEYRING)


class VerifyError(Exception):
    """A verification could not be attempted (missing or unreadable input)."""


@dataclass
class VerifyResult:
    """Outcome of one verification. Falsy when the model did not verify."""

    verified: bool
    model: str
    error: Optional[str] = None
    detail: Optional[str] = None
    sha256: Optional[str] = None
    fingerprint: Optional[str] = None
    trust: Optional[str] = None
    trusted_alias: Optional[str] = None
    signed_at: Optional[str] = None
    identity: dict = field(default_factory=dict)

    @property
    def trusted(self) -> bool:
        """True only when the signing identity was checked against a known key."""
        return self.verified and self.trust in _TRUSTED

    def __bool__(self) -> bool:
        return self.verified


def _hash_model(model_path: Path) -> tuple[Optional[dict], str]:
    if model_path.is_dir():
        return hash_directory(model_path)
    return None, hash_file(model_path)


def _message_for(model_path: Path, model_hash: str, identity_bytes: bytes) -> bytes:
    if model_path.is_dir():
        return build_dir_message(model_hash, identity_bytes)
    return build_file_message(model_hash, identity_bytes)


def default_sig_path(model_path: Path | str) -> Path:
    """Where a model's signature lives by convention: MODEL.sig beside it."""
    return Path(str(model_path) + ".sig")


def sign_model(
    model_path: Path | str,
    *,
    card: ModelCard | dict | None = None,
    name: str | None = None,
    key: Ed25519PrivateKey | Path | str | None = None,
    sig_path: Path | str | None = None,
    write: bool = True,
) -> SigFile:
    """Sign a model file or directory and return the signature.

    Provide either ``card`` (full identity) or ``name``. ``key`` may be a
    loaded private key or a path to a PEM; it defaults to the keygen location.
    """
    model_path = Path(model_path)
    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")

    if isinstance(key, Ed25519PrivateKey):
        private_key = key
    else:
        priv_path = Path(key) if key is not None else DEFAULT_KEY_DIR / "private.pem"
        if not priv_path.exists():
            raise VerifyError(f"no key found at {priv_path}. Run 'modelsign keygen' first.")
        private_key = load_private_key(priv_path)

    if card is None:
        if name is None:
            raise VerifyError("provide a name or an identity card")
        card = ModelCard(name=name)
    elif isinstance(card, dict):
        card = ModelCard.from_dict(card)
    validate_card(card)

    identity_dict = card.to_dict()
    identity_bytes = canonical_json(identity_dict)

    manifest, model_hash = _hash_model(model_path)
    message = _message_for(model_path, model_hash, identity_bytes)

    pub_key = private_key.public_key()
    sig = SigFile(
        modelsign_version="1.0",
        file=str(model_path) if model_path.is_dir() else model_path.name,
        sha256=f"sha256:{model_hash}",
        signature=base64.b64encode(sign_bytes(message, private_key)).decode("ascii"),
        algorithm="ed25519",
        signed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        public_key=base64.b64encode(public_key_to_bytes(pub_key)).decode("ascii"),
        key_fingerprint=compute_fingerprint(pub_key),
        identity=identity_dict,
        manifest=manifest,
    )

    if write:
        write_sig(sig, Path(sig_path) if sig_path else default_sig_path(model_path))
    return sig


def _resolve_public_key(
    sig: SigFile,
    pubkey: Path | str | None,
    keyring_dir: Path | str | None,
) -> tuple[Ed25519PublicKey, str, Optional[str]]:
    """Return (key, trust level, keyring alias) for verifying this signature."""
    if pubkey is not None:
        return load_public_key(Path(pubkey)), TRUST_PUBKEY, None

    kr_dir = Path(keyring_dir) if keyring_dir else DEFAULT_KEY_DIR / "keyring"
    for entry in keyring_list(kr_dir):
        if entry["fingerprint"] == sig.key_fingerprint:
            return load_public_key(Path(entry["path"])), TRUST_KEYRING, entry["alias"]

    raw = base64.b64decode(sig.public_key)
    return Ed25519PublicKey.from_public_bytes(raw), TRUST_EMBEDDED, None


def verify_model(
    model_path: Path | str,
    *,
    sig_path: Path | str | None = None,
    pubkey: Path | str | None = None,
    keyring_dir: Path | str | None = None,
    require_trusted: bool = False,
) -> VerifyResult:
    """Verify a model against its signature.

    Returns a :class:`VerifyResult`; a failed check is a falsy result, not an
    exception. :class:`VerifyError` is raised only when the check cannot be
    attempted at all (model or signature missing or unreadable).

    With ``require_trusted``, a signature that can only be checked against its
    own embedded key is reported as unverified — use it wherever the identity
    of the signer matters, not just the integrity of the bytes.
    """
    model_path = Path(model_path)
    sig_file = Path(sig_path) if sig_path else default_sig_path(model_path)

    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")
    if not sig_file.exists():
        raise VerifyError(f"sig file not found: {sig_file}")

    try:
        sig = read_sig(sig_file, validate_fingerprint=True)
    except ValueError as e:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="corrupted sig",
            detail=str(e),
        )

    key, trust, alias = _resolve_public_key(sig, pubkey, keyring_dir)
    fingerprint = compute_fingerprint(key)

    # A signature names the file it was made for. Without this check a pair of
    # signed files could be swapped for each other — shard 1 presented as
    # shard 2 — since each still matches its own signature.
    if not model_path.is_dir() and sig.file != model_path.name:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="name mismatch",
            detail=f"signature was made for {sig.file!r}, not {model_path.name!r}",
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
        )

    _, model_hash = _hash_model(model_path)

    # Integrity before authenticity: a modified file is reported as such even
    # when the signature over the original bytes is itself intact.
    expected = sig.sha256[7:] if sig.sha256.startswith("sha256:") else sig.sha256
    if model_hash != expected:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="hash mismatch",
            detail="file has been modified since signing",
            sha256=f"sha256:{model_hash}",
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
        )

    message = _message_for(model_path, model_hash, canonical_json(sig.identity))
    try:
        signature_bytes = base64.b64decode(sig.signature)
    except Exception as e:
        raise VerifyError(f"could not decode signature: {e}") from e

    if not verify_bytes(message, signature_bytes, key):
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="invalid signature",
            detail="signature or identity card has been tampered with",
            sha256=f"sha256:{model_hash}",
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
        )

    if require_trusted and trust not in _TRUSTED:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="untrusted key",
            detail=(
                f"signed by {fingerprint}, which is not in the keyring; "
                "add it with 'modelsign trust' or pass a public key"
            ),
            sha256=f"sha256:{model_hash}",
            fingerprint=fingerprint,
            trust=trust,
            signed_at=sig.signed_at,
            identity=sig.identity,
        )

    return VerifyResult(
        verified=True,
        model=str(model_path),
        sha256=f"sha256:{model_hash}",
        fingerprint=fingerprint,
        trust=trust,
        trusted_alias=alias,
        signed_at=sig.signed_at,
        identity=sig.identity,
    )
