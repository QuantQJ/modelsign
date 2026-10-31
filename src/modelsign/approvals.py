"""Countersignatures: who approved this model, not just who built it.

A signature says a model's bytes and card are authentic. Deployment usually
needs a second claim — that a named person or role signed off on releasing it.
An approval is a separate signature over the digest of the model's signature,
appended to the same ``.sig``.

Approvals form a chain. Each one signs its own fields, the digest of the
model's signature, its position in the sequence, and the digest of the
approval before it. Three consequences, and it is worth being exact about
which is which:

* **Editing** any approval breaks that approval.
* **Removing or reordering** an approval that has another after it breaks
  every later one, because each committed to the exact bytes of its
  predecessor and to its own index.
* **Removing a trailing approval** — the last one, or all of them — still
  leaves no trace, because nothing inside the file counts what should be
  there. The model's own signature cannot help: approvals are appended after
  it was made. This is the irreducible part, and the answer to it is policy at
  verification time (``--require-approval``, ``--min-approvals``) or an
  external anchor such as a transparency log, not a cleverer signature.
"""

from __future__ import annotations

import base64
import hashlib
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
from modelsign.identity.canonical import canonical_json
from modelsign.sig import SigFile, read_sig, sig_digest, write_sig

__all__ = [
    "Approval",
    "ApprovalError",
    "approval_digest",
    "approve",
    "read_approvals",
    "require_approval",
]


class ApprovalError(Exception):
    """An approval could not be added or read."""


def build_approval_message(
    *,
    role: str,
    approver: str,
    signature_digest: str,
    approved_at: str,
    index: int,
    prev_digest: str,
) -> bytes:
    """The bytes an approval covers.

    ``index`` is its position in the sequence and ``prev_digest`` the digest of
    the approval before it (empty for the first), which is what makes the
    chain hold: an approval cannot be removed, reordered or inserted without
    invalidating the one after it.

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
        + b":"
        + _length_prefixed(str(index))
        + b":"
        + _length_prefixed(prev_digest)
    )


def approval_digest(record: dict) -> str:
    """Digest of one approval record, over its canonical JSON.

    Includes the record's own signature, so the next approval in the chain
    commits to every byte of this one.
    """
    return "sha256:" + hashlib.sha256(canonical_json(record)).hexdigest()


@dataclass
class Approval:
    """One countersignature on a model's signature."""

    role: str
    approver: str
    approved_at: str
    key_fingerprint: str
    public_key: str = ""
    index: int = 0
    valid: bool = False
    trusted: bool = False
    trusted_alias: Optional[str] = None
    chain_ok: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        """Valid, in an unbroken chain, and made by a key we already had."""
        return self.valid and self.chain_ok and self.trusted


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

    existing = list(sig.approvals or [])
    fingerprint = compute_fingerprint(public_key)
    if any(
        a.get("key_fingerprint") == fingerprint and a.get("role") == role
        for a in existing
    ):
        raise ApprovalError(
            f"{fingerprint} has already approved this signature as {role!r}"
        )

    # Chain this approval to the one before it, so neither can be removed
    # without breaking this one.
    index = len(existing)
    prev_digest = approval_digest(existing[-1]) if existing else ""

    message = build_approval_message(
        role=role,
        approver=approver,
        signature_digest=digest,
        approved_at=approved_at,
        index=index,
        prev_digest=prev_digest,
    )
    record = {
        "role": role,
        "approver": approver,
        "approved_at": approved_at,
        "signature_digest": digest,
        "index": index,
        "prev": prev_digest,
        "public_key": base64.b64encode(public_key_to_bytes(public_key)).decode("ascii"),
        "key_fingerprint": fingerprint,
        "signature": base64.b64encode(sign_bytes(message, private_key)).decode("ascii"),
    }
    existing.append(record)
    sig.approvals = existing
    write_sig(sig, sig_file)

    return Approval(
        role=role,
        approver=approver,
        approved_at=approved_at,
        key_fingerprint=fingerprint,
        index=index,
        valid=True,
        trusted=True,
        chain_ok=True,
    )


def _trusted_keys(
    pubkeys: Iterable[Path | str], keyring_dir: Path | str | None
) -> dict[bytes, str]:
    """Raw public key bytes -> alias, for keys the verifier already holds.

    Keyed on the whole key, not on ``compute_fingerprint``: that is eight hex
    characters, documented as display-only, and 32 bits is cheap to collide.
    Trusting on a fingerprint match would let anyone grind a key that collides
    with an approver's and have their own approval accepted.
    """
    trusted: dict[bytes, str] = {}
    for path in pubkeys:
        try:
            key = load_public_key(Path(path).expanduser())
        except Exception:
            continue
        trusted[public_key_to_bytes(key)] = Path(path).stem
    if keyring_dir is not None:
        for entry in keyring_list(Path(keyring_dir).expanduser()):
            try:
                key = load_public_key(Path(entry["path"]))
            except Exception:
                continue
            trusted.setdefault(public_key_to_bytes(key), entry["alias"])
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
    trusted = _trusted_keys(pubkeys, keyring_dir)

    results = []
    expected_prev = ""
    chain_intact = True
    for position, record in enumerate(sig.approvals or []):
        role = str(record.get("role", ""))
        approver = str(record.get("approver", ""))
        approved_at = str(record.get("approved_at", ""))
        fingerprint = str(record.get("key_fingerprint", ""))
        index = record.get("index", position)

        error = None
        valid = False
        raw_key = b""
        # An approval naming a different signature is not valid here, whatever
        # its own cryptography says.
        if record.get("signature_digest") != digest:
            error = "signed over a different signature"
        else:
            try:
                raw_key = base64.b64decode(record["public_key"])
                key = Ed25519PublicKey.from_public_bytes(raw_key)
                valid = compute_fingerprint(key) == fingerprint and verify_bytes(
                    build_approval_message(
                        role=role,
                        approver=approver,
                        signature_digest=digest,
                        approved_at=approved_at,
                        index=int(index),
                        prev_digest=str(record.get("prev", "")),
                    ),
                    base64.b64decode(record["signature"]),
                    key,
                )
            except Exception:
                valid = False
            if not valid:
                error = "invalid signature"

        # The chain: this approval must sit where it says it does and name the
        # exact bytes of the one before it. A break taints this and every
        # later approval, which is what makes a removal in the middle visible.
        chain_ok = chain_intact
        if int(index) != position:
            chain_ok = False
            error = error or f"out of sequence (claims {index}, is at {position})"
        elif str(record.get("prev", "")) != expected_prev:
            chain_ok = False
            error = error or "does not follow the approval before it"
        if not chain_ok:
            chain_intact = False
            error = error or "follows a broken link in the chain"

        results.append(
            Approval(
                role=role,
                approver=approver,
                approved_at=approved_at,
                key_fingerprint=fingerprint,
                index=int(index) if str(index).lstrip("-").isdigit() else position,
                public_key=record.get("public_key", ""),
                valid=valid,
                trusted=valid and chain_ok and raw_key in trusted,
                trusted_alias=trusted.get(raw_key) if valid and chain_ok else None,
                chain_ok=chain_ok,
                error=error,
            )
        )
        expected_prev = approval_digest(record)

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

    Only approvals that are valid, in an unbroken chain, and made by a key the
    verifier already holds can satisfy a policy — an approval signed by a key
    that arrived with the model proves nothing.

    Every role in ``roles`` must be satisfied, not merely one of them, and
    ``count`` counts **distinct** approvers: two approvals from one key are one
    person however many roles they are recorded under.
    """
    approvals = read_approvals(sig, pubkeys=pubkeys, keyring_dir=keyring_dir)
    usable = [a for a in approvals if a.ok]

    wanted_roles = list(dict.fromkeys(roles))
    wanted_keys = {f for f in fingerprints}

    if wanted_keys:
        usable = [a for a in usable if a.key_fingerprint in wanted_keys]

    # Every role asked for has to be satisfied, not any one of them.
    missing = [role for role in wanted_roles if not any(a.role == role for a in usable)]
    if missing:
        raise ApprovalError(
            "missing trusted approval for role(s): "
            + ", ".join(missing)
            + f"; {len(approvals)} approval(s) present in total, "
            f"{len(usable)} usable"
        )

    if wanted_roles:
        usable = [a for a in usable if a.role in wanted_roles]

    # A quorum counts distinct signing identities. Two approvals from one key,
    # in two roles, are one person.
    distinct = {a.public_key for a in usable if a.public_key}
    if len(distinct) < count:
        detail = []
        if wanted_roles:
            detail.append("role in " + ", ".join(sorted(wanted_roles)))
        if wanted_keys:
            detail.append("key in " + ", ".join(sorted(wanted_keys)))
        constraint = (" (" + "; ".join(detail) + ")") if detail else ""
        raise ApprovalError(
            f"needed {count} distinct trusted approver(s){constraint}, "
            f"found {len(distinct)}; {len(approvals)} approval(s) present in total"
        )
    return usable
