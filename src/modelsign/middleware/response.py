"""Ed25519 response signing for API authenticity."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from modelsign.crypto.keys import load_private_key
from modelsign.identity.canonical import canonical_json


class ResponseSigner:
    """Signs API responses with Ed25519 for authenticity verification."""

    def __init__(self, key_path: str | Path):
        self._private_key = load_private_key(Path(key_path).expanduser())
        self._public_key = self._private_key.public_key()

    def sign(self, data: dict) -> dict:
        """Sign response data. Returns envelope with data, signature, timestamp, fingerprint."""
        timestamp = datetime.now(timezone.utc).isoformat()
        canonical = canonical_json(data)
        fingerprint = hashlib.sha256(canonical).hexdigest()[:16]

        message = b"modelsign-v1:response:" + canonical + b":" + timestamp.encode("utf-8")
        signature = self._private_key.sign(message)

        return {
            "data": data,
            "signature": base64.b64encode(signature).decode(),
            "timestamp": timestamp,
            "fingerprint": fingerprint,
        }

    def get_public_key_pem(self) -> str:
        """Export public key PEM for verification by clients."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
