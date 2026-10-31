"""Countersignatures: who approved this model, not just who built it.

A signature says a model's bytes and card are authentic. Deployment usually
needs a second claim — that a named person or role signed off on releasing it.
An approval is a separate signature over the digest of the model's signature,
appended to the same ``.sig``.

Be exact about what this does and does not prove. Each approval is
self-authenticating: edit its role, its timestamp or the signature it points
at and it stops verifying. But approvals are added *after* the model was
signed, so the model's own signature does not cover them — **removing** an
approval leaves no trace. Presence is therefore something a verifier must
require by policy (``--require-approval``), never something to infer from a
signature that happens to carry one.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

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
from modelsign.crypto.sign import _length_prefixed, sign_bytes
from modelsign.crypto.verify import verify_bytes
from modelsign.sig import SigFile, read_sig, sig_digest, write_sig

__all__ = ["Approval", "ApprovalError", "approve", "read_approvals", "require_approval"]


class ApprovalError(Exception):
    """An approval could not be added or read."""


def build_approval_message(
    *, role: str, approver: str, signature_digest: str, approved_at: str
) -> bytes:
    """The bytes an approval covers.

    Every field is length-prefixed, so a role containing ":" cannot shift the
    boundaries — the same reason the v2 model message prefixes lengths.
    """
    return (
        b"modelsign-v2:approval:"
        + _length_prefixed(role)
        + b":"
        + _length_prefixed(approver)
        + b":"
        + _length_prefixed(signature_digest)
        + b":"
        + _length_prefixed(approved_at)
    )


@dataclass
class Approval:
    """One countersignature on a model's signature."""

    role: str
    approver: str
    approved_at: str
    key_fingerprint: str
    valid: bool = False
    trusted: bool = False
    trusted_alias: Optional[str] = None

    @property
    def ok(self) -> bool:
        """Valid and made by a key we already had."""
        return self.valid and self.trusted


def approve(
    model_path: Path | str,
    *,
    key: Ed25519PrivateKey | Path | str,
    role: str,
    approver: str = "",
    sig_path: Path | str | None = None,
    when: str | None = None,
) -> Approval:
    """Append an approval to a model's signature.

    The approval is signed over the digest of that signature, so it cannot be
    moved to a different model or a re-signed version of this one.
    """
    from modelsign.api import default_sig_path

    if not role or not role.strip():
        raise ApprovalError("an approval needs a role")

    model_path = Path(model_path).expanduser()
    sig_file = Path(sig_path).expanduser() if sig_path else default_sig_path(model_path)
    if not sig_file.exists():
        raise ApprovalError(f"no signature at {sig_file}; sign the model first")

    sig = read_sig(sig_file)
    digest = sig_digest(sig)

    private_key = key if isinstance(key, Ed25519PrivateKey) else load_private_key(Path(key))
    public_key = private_key.public_key()
    approved_at = when or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    message = build_approval_message(
        role=role, approver=approver, signature_digest=digest, approved_at=approved_at
    )
    record = {
        "role": role,
        "approver": approver,
        "approved_at": approved_at,
        "signature_digest": digest,
        "public_key": base64.b64encode(public_key_to_bytes(public_key)).decode("ascii"),
        "key_fingerprint": compute_fingerprint(public_key),
        "signature": base64.b64encode(sign_bytes(message, private_key)).decode("ascii"),
    }

    existing = list(sig.approvals or [])
    if any(
        a.get("key_fingerprint") == record["key_fingerprint"]
        and a.get("role") == role
        for a in existing
    ):
        raise ApprovalError(
            f"{record['key_fingerprint']} has already approved this signature as {role!r}"
        )
    existing.append(record)
    sig.approvals = existing
    write_sig(sig, sig_file)

    return Approval(
        role=role,
        approver=approver,
        approved_at=approved_at,
        key_fingerprint=record["key_fingerprint"],
        valid=True,
        trusted=True,
    )


def _trusted_fingerprints(
    pubkeys: Iterable[Path | str], keyring_dir: Path | str | None
) -> dict[str, str]:
    """Fingerprint -> alias, for keys the verifier already holds."""
    trusted: dict[str, str] = {}
    for path in pubkeys:
        try:
            key = load_public_key(Path(path).expanduser())
        except Exception:
            continue
        trusted[compute_fingerprint(key)] = Path(path).stem
    if keyring_dir is not None:
        for entry in keyring_list(Path(keyring_dir).expanduser()):
            trusted.setdefault(entry["fingerprint"], entry["alias"])
    return trusted


def read_approvals(
    sig: SigFile | Path | str,
    *,
    pubkeys: Iterable[Path | str] = (),
    keyring_dir: Path | str | None = None,
) -> list[Approval]:
    """Verify every approval on a signature.

    An approval whose signature does not check out comes back with
    ``valid=False`` rather than being dropped, so a caller can see that
    something was tampered with instead of merely missing.
    """
    if not isinstance(sig, SigFile):
        sig = read_sig(Path(sig))

    digest = sig_digest(sig)
    trusted = _trusted_fingerprints(pubkeys, keyring_dir)

    results = []
    for record in sig.approvals or []:
        role = str(record.get("role", ""))
        approver = str(record.get("approver", ""))
        approved_at = str(record.get("approved_at", ""))
        fingerprint = str(record.get("key_fingerprint", ""))

        valid = False
        # An approval naming a different signature is not valid here, whatever
        # its own cryptography says.
        if record.get("signature_digest") == digest:
            try:
                key = Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(record["public_key"])
                )
                valid = compute_fingerprint(key) == fingerprint and verify_bytes(
                    build_approval_message(
                        role=role,
                        approver=approver,
                        signature_digest=digest,
                        approved_at=approved_at,
                    ),
                    base64.b64decode(record["signature"]),
                    key,
                )
            except Exception:
                valid = False

        results.append(
            Approval(
                role=role,
                approver=approver,
                approved_at=approved_at,
                key_fingerprint=fingerprint,
                valid=valid,
                trusted=valid and fingerprint in trusted,
                trusted_alias=trusted.get(fingerprint) if valid else None,
            )
        )
    return results


def require_approval(
    sig: SigFile | Path | str,
    *,
    fingerprints: Iterable[str] = (),
    roles: Iterable[str] = (),
    count: int = 1,
    pubkeys: Iterable[Path | str] = (),
    keyring_dir: Path | str | None = None,
) -> list[Approval]:
    """Return the approvals satisfying a policy, or raise :class:`ApprovalError`.

    Only approvals that are both valid and made by a key the verifier already
    holds can satisfy a policy — an approval signed by a key that arrived with
    the model proves nothing.
    """
    approvals = read_approvals(sig, pubkeys=pubkeys, keyring_dir=keyring_dir)
    wanted_fingerprints = {f for f in fingerprints}
    wanted_roles = {r for r in roles}

    matching = [
        a
        for a in approvals
        if a.ok
        and (not wanted_fingerprints or a.key_fingerprint in wanted_fingerprints)
        and (not wanted_roles or a.role in wanted_roles)
    ]
    if len(matching) < count:
        detail = []
        if wanted_roles:
            detail.append("role in " + ", ".join(sorted(wanted_roles)))
        if wanted_fingerprints:
            detail.append("key in " + ", ".join(sorted(wanted_fingerprints)))
        constraint = (" (" + "; ".join(detail) + ")") if detail else ""
        raise ApprovalError(
            f"needed {count} trusted approval(s){constraint}, found {len(matching)}; "
            f"{len(approvals)} approval(s) present in total"
        )
    return matching
