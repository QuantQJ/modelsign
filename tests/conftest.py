"""Shared test fixtures for modelsign."""

import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def tmp_keypair(tmp_path):
    """Generate a temporary Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"

    priv_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    return {"private": priv_path, "public": pub_path, "key": private_key}


@pytest.fixture
def tmp_model_file(tmp_path):
    """Create a small fake model file for testing."""
    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model-weights-" + os.urandom(64))
    return model_path


@pytest.fixture
def tmp_model_dir(tmp_path):
    """Create a fake multi-file model directory for testing."""
    model_dir = tmp_path / "model_dir"
    model_dir.mkdir()
    (model_dir / "shard-00001.safetensors").write_bytes(b"shard1-" + os.urandom(32))
    (model_dir / "shard-00002.safetensors").write_bytes(b"shard2-" + os.urandom(32))
    (model_dir / "config.json").write_bytes(b'{"model_type": "llama"}')
    return model_dir


@pytest.fixture
def write_v1_sig():
    """Build a modelsign 1.x signature, whose `file` field is not signed.

    Lives here rather than in a test module so both test files can use it:
    importing across test modules depends on the rootdir being on sys.path,
    which held locally and did not in CI.
    """
    def _write(model_path, keypair, claimed_name=None):
        """Hand-build a modelsign 1.x signature, whose `file` field is unsigned."""
        import base64
        import time

        from modelsign.crypto.keys import (
            compute_fingerprint,
            load_private_key,
            public_key_to_bytes,
        )
        from modelsign.crypto.sign import build_file_message, sign_bytes
        from modelsign.formats.single import hash_file
        from modelsign.identity.canonical import canonical_json
        from modelsign.identity.card import ModelCard
        from modelsign.api import default_sig_path
        from modelsign.sig import SigFile, write_sig

        key = load_private_key(keypair["private"])
        identity = ModelCard(name="Legacy").to_dict()
        digest = hash_file(model_path)
        signature = sign_bytes(
            build_file_message(digest, canonical_json(identity)), key
        )
        sig = SigFile(
            modelsign_version="1.0",
            file=claimed_name or model_path.name,
            sha256=f"sha256:{digest}",
            signature=base64.b64encode(signature).decode(),
            algorithm="ed25519",
            signed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            public_key=base64.b64encode(public_key_to_bytes(key.public_key())).decode(),
            key_fingerprint=compute_fingerprint(key.public_key()),
            identity=identity,
        )
        write_sig(sig, default_sig_path(model_path))
        return sig


    return _write
