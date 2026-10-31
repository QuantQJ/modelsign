"""Interoperability with OpenSSF Model Signing (OMS).

OMS is the OpenSSF/sigstore format produced by the ``model-signing`` package:
one Sigstore bundle holding a DSSE envelope over an in-toto statement whose
predicate lists every file's digest. modelsign's own ``.sig`` carries the same
information, so this module translates between them — read an OMS bundle and
verify it, or sign a model so an OMS verifier accepts it.

Two constraints come from their implementation, both verified against it:

* OMS key signing is **ECDSA only** — it rejects Ed25519 keys outright, so
  bundles are signed with a P-256 key rather than modelsign's Ed25519 key.
* ``.git``, ``.github``, ``.gitattributes`` and ``.gitignore`` are excluded
  from the manifest by default, and that exclusion is recorded in the
  signature so a verifier applies the same rule.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from modelsign.api import TRUST_PUBKEY, VerifyError, VerifyResult
from modelsign.formats.single import hash_file

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://model_signing/signature/v1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: Paths OMS leaves out of the manifest by default.
DEFAULT_IGNORE_PATHS = (".git", ".github", ".gitattributes", ".gitignore")

#: Conventional bundle filename used by the model-signing CLI.
DEFAULT_BUNDLE_NAME = "model.sig"


class OMSError(Exception):
    """An OMS bundle could not be read, written or trusted."""


# -- primitives ---------------------------------------------------------


def pae(payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding of a payload (dsse protocol v1.0.0)."""
    header = f"DSSEv1 {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE} {len(payload)}"
    return b" ".join([header.encode("utf-8"), payload])


def pae_compat(payload: bytes) -> bytes:
    """PAE as model_signing 0.2.0 wrote it.

    That version interpolated the payload bytes into a string, so the signed
    message contains a Python bytes repr. Signatures from it only verify
    against this encoding.
    """
    header = f"DSSEV1 {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE} {len(payload)} {payload}"
    return header.encode("utf-8")


def key_hint(public_key: ec.EllipticCurvePublicKey) -> str:
    """The bundle's public key hint: SHA-256 over the public key's PEM."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pem).hexdigest()


def manifest_digest(digests: Sequence[str]) -> str:
    """The statement's subject digest: SHA-256 over the raw per-file digests."""
    hasher = hashlib.sha256()
    for digest in digests:
        hasher.update(bytes.fromhex(digest))
    return hasher.hexdigest()


def generate_ec_keypair(key_dir: Path | str) -> tuple[Path, Path]:
    """Write a P-256 keypair for OMS signing. Existing keys are left alone."""
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / "oms_private.pem"
    pub_path = key_dir / "oms_public.pem"
    if priv_path.exists() and pub_path.exists():
        return priv_path, pub_path

    key = ec.generate_private_key(ec.SECP256R1())
    priv_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o600)
    pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def load_ec_private_key(path: Path | str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise OMSError(
            f"OMS signing needs an ECDSA private key, got {type(key).__name__}. "
            "Generate one with 'modelsign oms keygen' — the model-signing "
            "verifier rejects Ed25519 keys."
        )
    return key


def load_ec_public_key(path: Path | str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise OMSError(
            f"OMS verification needs an ECDSA public key, got {type(key).__name__}."
        )
    return key


# -- manifest -----------------------------------------------------------


@dataclass
class Resource:
    name: str
    digest: str
    algorithm: str = "sha256"

    def to_dict(self) -> dict:
        return {"digest": self.digest, "algorithm": self.algorithm, "name": self.name}


def _ignored(rel: Path, ignore_paths: Iterable[str]) -> bool:
    """True when a relative path is excluded by the manifest's ignore list.

    An entry matches the path itself or a directory it sits under, the way
    model-signing resolves ignore_paths. It deliberately does not match a
    same-named file deeper in the tree: an added ``sub/.gitignore`` is an
    unsigned file, not an ignored one.
    """
    candidates = {rel.as_posix(), *(parent.as_posix() for parent in rel.parents)}
    return any(ignored in candidates for ignored in ignore_paths)


def collect_resources(
    model_path: Path | str,
    *,
    ignore_paths: Iterable[str] = DEFAULT_IGNORE_PATHS,
    allow_symlinks: bool = False,
) -> list[Resource]:
    """Hash every file OMS would include, sorted by name as their tool sorts."""
    model_path = Path(model_path)
    if model_path.is_file():
        return [Resource(name=model_path.name, digest=hash_file(model_path))]

    resources = []
    for path in model_path.rglob("*"):
        if not path.is_file():
            continue
        if not allow_symlinks and path.is_symlink():
            raise OMSError(
                f"{path.relative_to(model_path)} is a symlink; pass allow_symlinks "
                "to include it, as the model-signing CLI requires too."
            )
        rel = path.relative_to(model_path)
        if _ignored(rel, ignore_paths):
            continue
        resources.append(Resource(name=rel.as_posix(), digest=hash_file(path)))

    resources.sort(key=lambda r: r.name)
    return resources


def build_statement(
    model_name: str,
    resources: Sequence[Resource],
    *,
    ignore_paths: Iterable[str] = DEFAULT_IGNORE_PATHS,
    allow_symlinks: bool = False,
) -> dict:
    """Build the in-toto statement OMS signs."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": model_name,
                "digest": {"sha256": manifest_digest([r.digest for r in resources])},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "serialization": {
                "method": "files",
                "ignore_paths": list(ignore_paths),
                "hash_type": "sha256",
                "allow_symlinks": allow_symlinks,
            },
            "resources": [r.to_dict() for r in resources],
        },
    }


# -- export -------------------------------------------------------------


def export_bundle(
    model_path: Path | str,
    *,
    key: ec.EllipticCurvePrivateKey | Path | str,
    name: str | None = None,
    out: Path | str | None = None,
    ignore_paths: Iterable[str] = DEFAULT_IGNORE_PATHS,
    allow_symlinks: bool = False,
    write: bool = True,
) -> dict:
    """Sign a model into an OMS bundle the model-signing CLI can verify."""
    model_path = Path(model_path)
    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")

    private_key = key if isinstance(key, ec.EllipticCurvePrivateKey) else load_ec_private_key(key)

    # A bundle stored inside the model directory cannot be part of its own
    # manifest, so it joins the ignore list — which is what model-signing does.
    bundle_path = Path(out) if out else model_path.parent / DEFAULT_BUNDLE_NAME
    ignore_paths = list(ignore_paths)
    if model_path.is_dir():
        try:
            inside = bundle_path.resolve().relative_to(model_path.resolve())
        except ValueError:
            inside = None
        if inside is not None and inside.as_posix() not in ignore_paths:
            ignore_paths.append(inside.as_posix())

    resources = collect_resources(
        model_path, ignore_paths=ignore_paths, allow_symlinks=allow_symlinks
    )
    if not resources:
        raise OMSError(f"nothing to sign in {model_path}")

    statement = build_statement(
        name or model_path.name,
        resources,
        ignore_paths=ignore_paths,
        allow_symlinks=allow_symlinks,
    )
    payload = json.dumps(statement, indent=2).encode("utf-8")
    signature = private_key.sign(pae(payload), ec.ECDSA(hashes.SHA256()))

    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "publicKey": {"hint": key_hint(private_key.public_key())},
            "tlogEntries": [],
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(payload).decode("ascii"),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{"sig": base64.b64encode(signature).decode("ascii"), "keyid": ""}],
        },
    }

    if write:
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle


# -- verify -------------------------------------------------------------


def _statement_from(bundle: dict) -> tuple[dict, bytes]:
    if bundle.get("mediaType") != BUNDLE_MEDIA_TYPE:
        raise OMSError(
            f"unexpected bundle media type {bundle.get('mediaType')!r}, "
            f"expected {BUNDLE_MEDIA_TYPE!r}"
        )
    envelope = bundle.get("dsseEnvelope") or {}
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise OMSError(f"unexpected payload type {envelope.get('payloadType')!r}")
    try:
        payload = base64.b64decode(envelope["payload"])
        statement = json.loads(payload)
    except Exception as e:
        raise OMSError(f"could not read the DSSE payload: {e}") from e
    if statement.get("_type") != STATEMENT_TYPE:
        raise OMSError(f"unexpected statement type {statement.get('_type')!r}")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise OMSError(f"unexpected predicate type {statement.get('predicateType')!r}")
    return statement, payload


def verify_bundle(
    model_path: Path | str,
    bundle_path: Path | str,
    *,
    pubkey: ec.EllipticCurvePublicKey | Path | str,
    allow_unsigned: bool = False,
) -> VerifyResult:
    """Verify a model against an OMS bundle.

    Checks the DSSE signature, every file digest in the predicate, and that no
    file on disk is missing from the manifest. A failed check is a falsy
    :class:`~modelsign.api.VerifyResult`; a malformed bundle raises
    :class:`OMSError`.
    """
    model_path = Path(model_path)
    bundle_path = Path(bundle_path)
    if not model_path.exists():
        raise VerifyError(f"model not found: {model_path}")
    if not bundle_path.exists():
        raise VerifyError(f"bundle not found: {bundle_path}")

    public_key = pubkey if isinstance(pubkey, ec.EllipticCurvePublicKey) else load_ec_public_key(pubkey)
    bundle = json.loads(bundle_path.read_text())
    statement, payload = _statement_from(bundle)

    hint = ((bundle.get("verificationMaterial") or {}).get("publicKey") or {}).get("hint")
    if hint and hint != key_hint(public_key):
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="wrong key",
            detail="the bundle was signed by a different key than the one supplied",
            fingerprint=key_hint(public_key)[:16],
        )

    signatures = (bundle.get("dsseEnvelope") or {}).get("signatures") or []
    if not signatures:
        raise OMSError("bundle carries no signature")
    raw_sig = base64.b64decode(signatures[0]["sig"])

    for encode in (pae, pae_compat):
        try:
            public_key.verify(raw_sig, encode(payload), ec.ECDSA(hashes.SHA256()))
            break
        except InvalidSignature:
            continue
    else:
        return VerifyResult(
            verified=False,
            model=str(model_path),
            error="invalid signature",
            detail="the DSSE envelope does not verify under this key",
            fingerprint=key_hint(public_key)[:16],
        )

    predicate = statement["predicate"]
    serialization_info = predicate.get("serialization") or {}
    ignore_paths = serialization_info.get("ignore_paths", list(DEFAULT_IGNORE_PATHS))
    signed = {r["name"]: r["digest"] for r in predicate.get("resources", [])}

    if not signed:
        raise OMSError("bundle signs no resources")

    if not model_path.is_dir():
        if len(signed) != 1 or model_path.name not in signed:
            raise OMSError(
                f"bundle covers {sorted(signed)} and cannot verify the single "
                f"file {model_path.name!r}; point it at the signed directory"
            )

    result_fields = dict(
        model=str(model_path),
        fingerprint=key_hint(public_key)[:16],
        trust=TRUST_PUBKEY,
        identity={"name": statement["subject"][0]["name"], "format": "oms"},
    )

    # Every signed file must be present and unchanged.
    for name, digest in sorted(signed.items()):
        target = model_path / name if model_path.is_dir() else model_path
        if not target.exists():
            return VerifyResult(
                verified=False, error="missing file",
                detail=f"{name} is in the signature but not on disk", **result_fields
            )
        if hash_file(target) != digest:
            return VerifyResult(
                verified=False, error="hash mismatch",
                detail=f"{name} has been modified since signing", **result_fields
            )

    # And nothing may ride along unsigned. Symlinks are counted whether or not
    # the signer allowed them: a Hugging Face cache is made entirely of
    # symlinks into blobs/, so skipping them would disable this check exactly
    # where it matters. Content stays pinned either way, because the digest
    # check above follows the link.
    if model_path.is_dir() and not allow_unsigned:
        on_disk = {
            p.relative_to(model_path).as_posix()
            for p in model_path.rglob("*")
            if (p.is_file() or p.is_symlink())
            and not _ignored(p.relative_to(model_path), ignore_paths)
        }
        extra = sorted(on_disk - set(signed))
        if extra:
            return VerifyResult(
                verified=False, error="unsigned files",
                detail="not covered by the signature: " + ", ".join(extra[:5]), **result_fields
            )

    expected_subject = statement["subject"][0]["digest"]["sha256"]
    recomputed = manifest_digest([signed[name] for name in sorted(signed)])
    if recomputed != expected_subject:
        return VerifyResult(
            verified=False, error="manifest digest mismatch",
            detail="the resource list does not hash to the signed subject digest",
            **result_fields
        )

    return VerifyResult(verified=True, sha256=f"sha256:{expected_subject}", **result_fields)
