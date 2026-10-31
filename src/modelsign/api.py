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
from modelsign.crypto.sign import (
    build_dir_message,
    build_file_message,
    build_file_message_v2,
    sign_bytes,
)
from modelsign.crypto.verify import verify_bytes
from modelsign.formats.directory import hash_directory
from modelsign.formats.single import hash_file
from modelsign.identity.canonical import canonical_json
from modelsign.identity.card import ModelCard, validate_card
from modelsign.sig import SigFile, read_sig, sig_digest, write_sig

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


class _CallerKeyError(Exception):
    """A key the caller supplied could not be loaded — their problem, not the sig's."""


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
    name_bound: bool = False
    """Whether the model's own name is covered by the signature.

    True for a single file signed with format 2.0 or later. False for a
    directory, whose own name is deliberately not signed — see ``paths_bound``.
    """

    paths_bound: bool = False
    """Whether the layout inside the model is covered by the signature.

    True for a directory signature, whose manifest hash covers every relative
    path, so a file cannot be added, removed or moved within it.
    """

    @property
    def trusted(self) -> bool:
        """True only when the signing identity was checked against a known key."""
        return self.verified and self.trust in _TRUSTED

    def __bool__(self) -> bool:
        return self.verified


def _major(version: str) -> int:
    """Major version of a .sig, 0 when it cannot be read."""
    try:
        return int(str(version).split(".")[0])
    except (ValueError, AttributeError, IndexError):
        return 0


def _hash_model(
    model_path: Path, sig_file: Optional[Path] = None
) -> tuple[Optional[dict], str]:
    """Hash a model, leaving out a signature stored inside it."""
    if not model_path.is_dir():
        return None, hash_file(model_path)

    exclude = []
    if sig_file is not None:
        try:
            exclude.append(
                Path(sig_file).resolve().relative_to(model_path.resolve()).as_posix()
            )
        except ValueError:
            pass  # the signature sits outside the directory; nothing to skip
    return hash_directory(model_path, exclude=exclude)


def _message_for(
    model_path: Path, model_hash: str, identity_bytes: bytes, *, name: str | None = None
) -> bytes:
    """The bytes a signature covers.

    With ``name``, the v2 format binds the model's name into the signed
    message. Without it, the v1 format is reproduced for reading old
    signatures, where the name was not authenticated.
    """
    if model_path.is_dir():
        # A directory signature covers the manifest hash, which already
        # authenticates every relative path inside it. The directory's own
        # name is not part of it: a snapshot lands under a different name on
        # the machine that verifies it than on the one that signed it.
        return build_dir_message(model_hash, identity_bytes)
    if name is None:
        return build_file_message(model_hash, identity_bytes)
    return build_file_message_v2(name, model_hash, identity_bytes)


def default_sig_path(model_path: Path | str) -> Path:
    """Where a model's signature lives by convention: MODEL.sig beside it."""
    return Path(str(Path(model_path).expanduser()) + ".sig")


def sign_model(
    model_path: Path | str,
    *,
    card: ModelCard | dict | None = None,
    name: str | None = None,
    key: Ed25519PrivateKey | Path | str | None = None,
    sig_path: Path | str | None = None,
    parent: Path | str | SigFile | None = None,
    write: bool = True,
) -> SigFile:
    """Sign a model file or directory and return the signature.

    Provide either ``card`` (full identity) or ``name``. ``key`` may be a
    loaded private key or a path to a PEM; it defaults to the keygen location.

    ``parent`` is the signature of the model this one was derived from; its
    digest is recorded in the card as ``parent_signature``, which
    :mod:`modelsign.lineage` walks. An explicit ``parent_signature`` already
    in the card wins.
    """
    model_path = Path(model_path).expanduser()
    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")

    if isinstance(key, Ed25519PrivateKey):
        private_key = key
    else:
        priv_path = Path(key).expanduser() if key is not None else DEFAULT_KEY_DIR / "private.pem"
        if not priv_path.exists():
            raise VerifyError(f"no key found at {priv_path}. Run 'modelsign keygen' first.")
        try:
            private_key = load_private_key(priv_path)
        except Exception as e:
            raise VerifyError(f"could not load the signing key {priv_path}: {e}") from e

    if card is None:
        if name is None:
            raise VerifyError("provide a name or an identity card")
        card = ModelCard(name=name)
    elif isinstance(card, dict):
        card = ModelCard.from_dict(card)

    if parent is not None and not card.parent_signature:
        card.parent_signature = sig_digest(parent)

    validate_card(card)

    identity_dict = card.to_dict()
    identity_bytes = canonical_json(identity_dict)

    bundle_sig_path = Path(sig_path) if sig_path else default_sig_path(model_path)

    manifest, model_hash = _hash_model(model_path, bundle_sig_path)
    message = _message_for(
        model_path, model_hash, identity_bytes, name=model_path.name
    )

    pub_key = private_key.public_key()
    sig = SigFile(
        modelsign_version="2.0",
        file=model_path.name,
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
        write_sig(sig, bundle_sig_path)
    return sig


def _resolve_public_key(
    sig: SigFile,
    pubkey: Path | str | None,
    keyring_dir: Path | str | None,
) -> tuple[Ed25519PublicKey, str, Optional[str]]:
    """Return (key, trust level, keyring alias) for verifying this signature."""
    if pubkey is not None:
        try:
            loaded = load_public_key(Path(pubkey).expanduser())
        except Exception as e:
            raise _CallerKeyError(f"could not load public key {pubkey}: {e}") from e
        return loaded, TRUST_PUBKEY, None

    kr_dir = Path(keyring_dir).expanduser() if keyring_dir else DEFAULT_KEY_DIR / "keyring"
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
    require_trusted: bool = True,
    require_name_binding: bool = True,
) -> VerifyResult:
    """Verify a model against its signature.

    Returns a :class:`VerifyResult`; a failed check is a falsy result, not an
    exception. :class:`VerifyError` is raised only when the check cannot be
    attempted at all (model or signature missing or unreadable).

    ``require_trusted`` is on by default: a signature that can only be checked
    against its own embedded key is reported as unverified, because anyone can
    generate a key. Pass False when you want integrity alone and have some
    other reason to trust the source.

    ``require_name_binding`` is on by default: a modelsign 1.x signature of a
    single file is rejected, because that format leaves the filename out of
    the signed message. Pass False only for old signatures you cannot
    re-sign.
    """
    model_path = Path(model_path).expanduser()
    sig_file = Path(sig_path).expanduser() if sig_path else default_sig_path(model_path)

    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")
    if not sig_file.exists():
        raise VerifyError(f"sig file not found: {sig_file}")

    # The .sig is attacker-supplied input, so every way it can be malformed —
    # an unsupported version, a missing field, a key that is not a key — is a
    # failed verification rather than an exception the caller must anticipate.
    try:
        sig = read_sig(sig_file, validate_fingerprint=True)
    except Exception as e:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="malformed sig",
            detail=f"{type(e).__name__}: {e}",
        )

    try:
        key, trust, alias = _resolve_public_key(sig, pubkey, keyring_dir)
    except _CallerKeyError as e:
        raise VerifyError(str(e)) from e
    except Exception as e:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="malformed sig",
            detail=f"unusable public key — {type(e).__name__}: {e}",
        )
    fingerprint = compute_fingerprint(key)

    # v2 puts the model's name inside the signed message. v1 did not, so a v1
    # .sig's `file` field is unauthenticated — comparing it is worth doing to
    # catch an accidental rename, but it stops nobody who can edit the file.
    # A directory's manifest hash covers every relative path inside it; a
    # single file's name is covered only by format 2.0 and later. Either
    # satisfies a caller asking that the signature bind the model's identity,
    # but they are not the same property, so they are reported separately.
    is_dir = model_path.is_dir()
    paths_bound = is_dir
    name_bound = (not is_dir) and _major(sig.modelsign_version) >= 2
    if require_name_binding and not (name_bound or paths_bound):
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="unauthenticated name",
            detail=(
                f"this signature is modelsign {sig.modelsign_version}, which does "
                "not cover the model's name; re-sign it to bind the name"
            ),
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
        )

    try:
        _, model_hash = _hash_model(model_path, sig_file)
    except OSError as e:
        raise VerifyError(f"could not read {model_path}: {e}") from e

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
            name_bound=name_bound,
            paths_bound=paths_bound,
        )

    identity_bytes = canonical_json(sig.identity)
    try:
        signature_bytes = base64.b64decode(sig.signature)
    except Exception as e:
        raise VerifyError(f"could not decode signature: {e}") from e

    # The name verified against is the one on disk, never the one the .sig
    # claims — otherwise the claim would authenticate itself.
    message = _message_for(
        model_path,
        model_hash,
        identity_bytes,
        name=model_path.name if name_bound else None,
    )

    if not verify_bytes(message, signature_bytes, key):
        error, detail = "invalid signature", "signature or identity card has been tampered with"
        if name_bound and sig.file != model_path.name:
            # Distinguish the common case for the error message only; this is
            # a failure either way.
            under_claimed_name = _message_for(
                model_path, model_hash, identity_bytes, name=sig.file
            )
            if verify_bytes(under_claimed_name, signature_bytes, key):
                error = "name mismatch"
                detail = f"signature was made for {sig.file!r}, not {model_path.name!r}"
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error=error,
            detail=detail,
            sha256=f"sha256:{model_hash}",
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
            name_bound=name_bound,
            paths_bound=paths_bound,
        )

    # A v1 signature cannot bind the name, so report a rename as best we can.
    if not name_bound and not is_dir and sig.file != model_path.name:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="name mismatch",
            detail=(
                f"signature claims {sig.file!r}, not {model_path.name!r} — note this "
                "field is unauthenticated in modelsign 1.x signatures"
            ),
            sha256=f"sha256:{model_hash}",
            fingerprint=fingerprint,
            trust=trust,
            trusted_alias=alias,
            signed_at=sig.signed_at,
            identity=sig.identity,
            name_bound=False,
            paths_bound=paths_bound,
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
            name_bound=name_bound,
            paths_bound=paths_bound,
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
        name_bound=name_bound,
        paths_bound=paths_bound,
    )
