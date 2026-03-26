"""Tests for response signing middleware."""

from pathlib import Path
from modelsign.middleware.response import ResponseSigner
from modelsign.crypto.keys import generate_keypair, load_public_key
from modelsign.crypto.verify import verify_bytes
from modelsign.identity.canonical import canonical_json
import base64


def test_sign_response(tmp_path):
    priv_path, pub_path = generate_keypair(tmp_path)
    signer = ResponseSigner(key_path=priv_path)

    data = {"prediction": "bullish", "confidence": 0.87}
    result = signer.sign(data)

    assert result["data"] == data
    assert "signature" in result
    assert "timestamp" in result
    assert "fingerprint" in result
    assert len(result["fingerprint"]) == 16


def test_verify_signed_response(tmp_path):
    priv_path, pub_path = generate_keypair(tmp_path)
    signer = ResponseSigner(key_path=priv_path)

    data = {"result": "ok"}
    result = signer.sign(data)

    public_key = load_public_key(pub_path)
    canonical = canonical_json(data)
    message = b"modelsign-v1:response:" + canonical + b":" + result["timestamp"].encode()
    signature = base64.b64decode(result["signature"])
    assert verify_bytes(message, signature, public_key) is True


def test_different_data_different_signature(tmp_path):
    priv_path, _ = generate_keypair(tmp_path)
    signer = ResponseSigner(key_path=priv_path)

    r1 = signer.sign({"a": 1})
    r2 = signer.sign({"a": 2})
    assert r1["signature"] != r2["signature"]
    assert r1["fingerprint"] != r2["fingerprint"]


def test_get_public_key_pem(tmp_path):
    priv_path, _ = generate_keypair(tmp_path)
    signer = ResponseSigner(key_path=priv_path)
    pem = signer.get_public_key_pem()
    assert "BEGIN PUBLIC KEY" in pem
