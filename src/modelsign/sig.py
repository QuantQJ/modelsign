"""Sig file I/O — reading, writing, and version management for .sig files."""

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


CURRENT_VERSION = "1.0"
SUPPORTED_MAJOR = 1


class SigVersionError(Exception):
    """Raised when .sig file version is incompatible."""
    pass


@dataclass
class SigFile:
    """In-memory representation of a .sig file."""

    modelsign_version: str
    file: str
    sha256: str
    signature: str
    algorithm: str
    signed_at: str
    public_key: str
    key_fingerprint: str
    identity: dict
    manifest: Optional[dict] = None


def write_sig(sig: SigFile, path: Path) -> None:
    """Write a SigFile to disk as human-readable JSON."""
    path = Path(path)
    data = asdict(sig)
    data = {k: v for k, v in data.items() if v is not None}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def read_sig(path: Path, validate_fingerprint: bool = False) -> SigFile:
    """Read a .sig file and validate version.

    Version policy:
    - Known version (1.0): load normally
    - Higher minor (1.x): warn to stderr, load
    - Higher major (2+): raise SigVersionError
    - Missing/malformed: raise SigVersionError
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Signature file not found: {path}")

    data = json.loads(path.read_text())

    version = data.get("modelsign_version")
    if not version or not isinstance(version, str):
        raise SigVersionError("invalid sig file: missing or malformed modelsign_version")

    try:
        parts = version.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        raise SigVersionError(f"invalid sig file: cannot parse version '{version}'")

    if major > SUPPORTED_MAJOR:
        raise SigVersionError(
            f"this sig requires modelsign v{major}+, please upgrade "
            f"(current: v{CURRENT_VERSION})"
        )

    if major == SUPPORTED_MAJOR and minor > 0:
        print(
            f"Warning: sig created with newer modelsign {version}, "
            f"some fields may be unrecognized",
            file=sys.stderr,
        )

    sig = SigFile(
        modelsign_version=data["modelsign_version"],
        file=data["file"],
        sha256=data["sha256"],
        signature=data["signature"],
        algorithm=data["algorithm"],
        signed_at=data["signed_at"],
        public_key=data["public_key"],
        key_fingerprint=data["key_fingerprint"],
        identity=data["identity"],
        manifest=data.get("manifest"),
    )

    if validate_fingerprint:
        _check_fingerprint(sig)

    return sig


def _check_fingerprint(sig: SigFile) -> None:
    """Validate that key_fingerprint matches public_key."""
    import base64
    import hashlib
    from modelsign.crypto.keys import FINGERPRINT_HEX_CHARS

    try:
        raw_key = base64.b64decode(sig.public_key)
        expected_fp = "ed25519:" + hashlib.sha256(raw_key).hexdigest()[:FINGERPRINT_HEX_CHARS]
        if sig.key_fingerprint != expected_fp:
            raise ValueError(
                f"fingerprint mismatch: sig says {sig.key_fingerprint}, "
                f"computed {expected_fp} from embedded public key"
            )
    except Exception as e:
        if "fingerprint mismatch" in str(e):
            raise
        raise ValueError(f"fingerprint validation failed: {e}")
