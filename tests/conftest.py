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
