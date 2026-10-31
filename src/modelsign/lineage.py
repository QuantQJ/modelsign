"""Provenance chains: verify a model back through the models it came from.

A signed card may carry ``parent_signature``, the digest of the signature of
the model this one was derived from. Walking that field turns a pile of
signatures into a chain — this fine-tune came from that base model, which came
from that one — and each link is checked cryptographically rather than taken
on trust.

An ancestor's weights are usually long gone, which is fine: a signature
records the hash it was made over, so the signature itself can be verified
from the ``.sig`` alone. What that proves is narrower and worth stating — the
ancestor's card and digest are authentic and unmodified, not that any
particular file on this machine is that ancestor.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modelsign.api import (
    TRUST_EMBEDDED,
    VerifyError,
    VerifyResult,
    _major,
    _resolve_public_key,
    default_sig_path,
    verify_model,
)
from modelsign.crypto.keys import compute_fingerprint
from modelsign.crypto.sign import (
    build_dir_message,
    build_file_message,
    build_file_message_v2,
)
from modelsign.crypto.verify import verify_bytes
from modelsign.identity.canonical import canonical_json
from modelsign.sig import SigFile, read_sig, sig_digest

__all__ = [
    "Link",
    "LineageResult",
    "sig_digest",
    "verify_signature_only",
    "index_signatures",
    "verify_lineage",
]


def _signed_message(sig: SigFile) -> bytes:
    """Rebuild the message a signature covers, from the signature alone."""
    digest = sig.sha256[7:] if sig.sha256.startswith("sha256:") else sig.sha256
    identity_bytes = canonical_json(sig.identity)
    if sig.manifest is not None:
        return build_dir_message(digest, identity_bytes)
    if _major(sig.modelsign_version) >= 2:
        return build_file_message_v2(sig.file, digest, identity_bytes)
    return build_file_message(digest, identity_bytes)


def verify_signature_only(
    sig: SigFile, key: Ed25519PublicKey | None = None
) -> bool:
    """Check a signature's own authenticity without needing the model file.

    ``key`` is the key to check against. Without one the signature's own
    embedded key is used, which proves internal consistency and nothing about
    who produced it — callers that care pass a trusted key.
    """
    try:
        if key is None:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(sig.public_key))
        return verify_bytes(_signed_message(sig), base64.b64decode(sig.signature), key)
    except Exception:
        return False


@dataclass
class Link:
    """One model in a chain."""

    depth: int
    sig_path: Optional[Path]
    digest: Optional[str] = None
    name: str = ""
    parent_digest: Optional[str] = None
    trusted_alias: Optional[str] = None
    signature_valid: bool = False
    key_trusted: bool = False
    key_fingerprint: Optional[str] = None
    bytes_verified: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.signature_valid and self.key_trusted and self.error is None


@dataclass
class LineageResult:
    """A chain walked from a model back towards its root."""

    verified: bool
    chain: list[Link] = field(default_factory=list)
    complete: bool = False
    error: Optional[str] = None

    @property
    def depth(self) -> int:
        return len(self.chain)

    def __bool__(self) -> bool:
        return self.verified


def index_signatures(search: Iterable[Path | str]) -> dict[str, Path]:
    """Map every ``.sig`` under these directories by its own digest."""
    index: dict[str, Path] = {}
    for root in search:
        root = Path(root)
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = sorted(root.rglob("*.sig"))
        else:
            continue
        for path in candidates:
            try:
                index.setdefault(sig_digest(path), path)
            except Exception:
                continue
    return index


def verify_lineage(
    model_path: Path | str,
    *,
    sig_path: Path | str | None = None,
    search: Iterable[Path | str] = (),
    pubkey: Path | str | None = None,
    keyring_dir: Path | str | None = None,
    require_complete: bool = False,
    require_name_binding: bool = True,
    require_trusted: bool = True,
    max_depth: int = 64,
) -> LineageResult:
    """Verify a model and then every ancestor its card points back to.

    The model itself is verified against its bytes. Each ancestor is located
    by its signature digest among ``search`` and verified from its signature,
    against a key resolved the same way the model's own key is — a supplied
    public key or the local keyring. ``require_trusted`` is on by default: an
    ancestor checkable only against the key bundled in its own ``.sig`` proves
    internal consistency and nothing about who made it, so a chain of forged
    ancestors cannot pass by default.

    A chain ends when a card records no parent; with ``require_complete`` a
    chain whose next link cannot be found is a failure rather than a stop.
    """
    model_path = Path(model_path)
    sig_file = Path(sig_path) if sig_path else default_sig_path(model_path)

    try:
        head: VerifyResult = verify_model(
            model_path,
            sig_path=sig_file,
            pubkey=pubkey,
            keyring_dir=keyring_dir,
            require_name_binding=require_name_binding,
            require_trusted=require_trusted,
        )
    except VerifyError as e:
        return LineageResult(verified=False, error=str(e))

    sig = read_sig(sig_file)
    chain = [
        Link(
            depth=0,
            sig_path=sig_file,
            digest=sig_digest(sig),
            name=sig.identity.get("name", ""),
            parent_digest=sig.identity.get("parent_signature"),
            signature_valid=head.verified,
            key_trusted=head.trusted or not require_trusted,
            key_fingerprint=head.fingerprint,
            bytes_verified=head.verified,
            error=head.error,
        )
    ]
    if not head.verified:
        return LineageResult(verified=False, chain=chain, error=head.error)

    index = index_signatures(search)
    seen = {chain[0].digest}
    parent = chain[0].parent_digest

    while parent is not None:
        if len(chain) >= max_depth:
            return LineageResult(
                verified=False, chain=chain, error=f"chain longer than {max_depth}"
            )
        if parent in seen:
            return LineageResult(
                verified=False, chain=chain, error="chain loops back on itself"
            )

        found = index.get(parent)
        if found is None:
            link = Link(depth=len(chain), sig_path=None, digest=parent,
                        error="parent signature not found")
            chain.append(link)
            if require_complete:
                return LineageResult(
                    verified=False, chain=chain,
                    error=f"parent {parent[:23]}... not found among the signatures searched",
                )
            return LineageResult(verified=True, chain=chain, complete=False)

        try:
            parent_sig = read_sig(found, validate_fingerprint=True)
        except Exception as e:
            chain.append(Link(depth=len(chain), sig_path=found, digest=parent,
                              error=f"malformed sig: {type(e).__name__}"))
            return LineageResult(
                verified=False, chain=chain,
                error=f"ancestor at depth {len(chain) - 1} could not be read",
            )

        # Same trust path as the model in hand: a supplied key or the keyring,
        # falling back to the sig's own key only to report that it did.
        try:
            key, trust, alias = _resolve_public_key(parent_sig, pubkey, keyring_dir)
        except Exception as e:
            chain.append(Link(depth=len(chain), sig_path=found, digest=parent,
                              error=f"unusable key: {type(e).__name__}"))
            return LineageResult(
                verified=False, chain=chain,
                error=f"ancestor at depth {len(chain) - 1} has no usable key",
            )

        valid = verify_signature_only(parent_sig, key)
        trusted = trust != TRUST_EMBEDDED
        error = None
        if not valid:
            error = "invalid signature"
        elif require_trusted and not trusted:
            error = "untrusted key"

        link = Link(
            depth=len(chain),
            sig_path=found,
            digest=parent,
            name=parent_sig.identity.get("name", ""),
            parent_digest=parent_sig.identity.get("parent_signature"),
            signature_valid=valid,
            key_trusted=trusted or not require_trusted,
            key_fingerprint=compute_fingerprint(key),
            trusted_alias=alias,
            error=error,
        )
        chain.append(link)
        if error is not None:
            return LineageResult(
                verified=False, chain=chain,
                error=f"ancestor at depth {link.depth}: {error}",
            )

        seen.add(parent)
        parent = link.parent_digest

    return LineageResult(verified=True, chain=chain, complete=True)
