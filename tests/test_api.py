"""Tests for the library-level sign/verify API."""

import pytest

from modelsign.api import (
    TRUST_EMBEDDED,
    TRUST_PUBKEY,
    VerifyError,
    default_sig_path,
    sign_model,
    verify_model,
)
from modelsign.crypto.keys import load_private_key
from modelsign.identity.card import ModelCard
from modelsign.sig import read_sig, write_sig


@pytest.fixture
def signed_file(tmp_keypair, tmp_model_file):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    return tmp_model_file


def test_sign_writes_sig_beside_model(tmp_keypair, tmp_model_file):
    sig = sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    assert default_sig_path(tmp_model_file).exists()
    assert sig.algorithm == "ed25519"
    assert sig.identity["name"] == "Test-Model"


def test_verify_roundtrip_is_trusted_with_pubkey(signed_file, tmp_keypair):
    result = verify_model(signed_file, pubkey=tmp_keypair["public"])
    assert result
    assert result.verified is True
    assert result.trust == TRUST_PUBKEY
    assert result.trusted is True
    assert result.identity["name"] == "Test-Model"


def test_embedded_key_verifies_but_is_not_trusted(signed_file, tmp_path):
    result = verify_model(signed_file, keyring_dir=tmp_path / "empty-keyring")
    assert result.verified is True
    assert result.trust == TRUST_EMBEDDED
    assert result.trusted is False


def test_require_trusted_rejects_embedded_key(signed_file, tmp_path):
    result = verify_model(
        signed_file, keyring_dir=tmp_path / "empty-keyring", require_trusted=True
    )
    assert not result
    assert result.error == "untrusted key"


def test_modified_weights_fail(signed_file, tmp_keypair):
    signed_file.write_bytes(b"different-weights")
    result = verify_model(signed_file, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "hash mismatch"


def test_tampered_identity_card_fails(signed_file, tmp_keypair):
    sig_path = default_sig_path(signed_file)
    sig = read_sig(sig_path)
    sig.identity["name"] = "Someone-Elses-Model"
    write_sig(sig, sig_path)

    result = verify_model(signed_file, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "invalid signature"


def test_wrong_key_fails(signed_file, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = tmp_path / "other.pem"
    other.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    result = verify_model(signed_file, pubkey=other)
    assert not result
    assert result.error == "invalid signature"


def test_directory_roundtrip(tmp_keypair, tmp_model_dir):
    sign_model(tmp_model_dir, name="Sharded-Model", key=tmp_keypair["private"])
    result = verify_model(tmp_model_dir, pubkey=tmp_keypair["public"])
    assert result
    assert result.identity["name"] == "Sharded-Model"


def test_directory_detects_added_shard(tmp_keypair, tmp_model_dir):
    sign_model(tmp_model_dir, name="Sharded-Model", key=tmp_keypair["private"])
    (tmp_model_dir / "shard-00003.safetensors").write_bytes(b"smuggled")
    result = verify_model(tmp_model_dir, pubkey=tmp_keypair["public"])
    assert not result


def test_full_identity_card_survives_roundtrip(tmp_keypair, tmp_model_file):
    card = ModelCard.from_dict(
        {
            "name": "Llama-3.1-8B-QJ",
            "base_model": "meta-llama/Llama-3.1-8B-Instruct",
            "eval_metrics": {"mmlu": 0.68},
        }
    )
    sign_model(tmp_model_file, card=card, key=tmp_keypair["private"])
    result = verify_model(tmp_model_file, pubkey=tmp_keypair["public"])
    assert result.identity["base_model"] == "meta-llama/Llama-3.1-8B-Instruct"
    assert result.identity["eval_metrics"] == {"mmlu": 0.68}


def test_sign_accepts_loaded_key_object(tmp_keypair, tmp_model_file):
    key = load_private_key(tmp_keypair["private"])
    sign_model(tmp_model_file, name="Test-Model", key=key)
    assert verify_model(tmp_model_file, pubkey=tmp_keypair["public"])


def test_missing_model_raises(tmp_path):
    with pytest.raises(VerifyError):
        verify_model(tmp_path / "nope.safetensors")


def test_missing_sig_raises(tmp_model_file):
    with pytest.raises(VerifyError):
        verify_model(tmp_model_file)


def test_sign_without_name_or_card_raises(tmp_keypair, tmp_model_file):
    with pytest.raises(VerifyError):
        sign_model(tmp_model_file, key=tmp_keypair["private"])
