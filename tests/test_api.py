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


def test_signature_is_bound_to_its_filename(tmp_keypair, tmp_path):
    """Two signed shards must not be swappable for each other."""
    first = tmp_path / "model-00001-of-00002.safetensors"
    second = tmp_path / "model-00002-of-00002.safetensors"
    first.write_bytes(b"shard-one")
    second.write_bytes(b"shard-two")
    sign_model(first, name="Sharded", key=tmp_keypair["private"])
    sign_model(second, name="Sharded", key=tmp_keypair["private"])

    # Present shard one, and its signature, under shard two's name.
    swapped = tmp_path / "swapped" / second.name
    swapped.parent.mkdir()
    swapped.write_bytes(first.read_bytes())
    (tmp_path / "swapped" / (second.name + ".sig")).write_bytes(
        default_sig_path(first).read_bytes()
    )

    result = verify_model(swapped, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "name mismatch"


def test_renaming_a_signed_file_fails(tmp_keypair, tmp_model_file, tmp_path):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    renamed = tmp_path / "renamed.safetensors"
    renamed.write_bytes(tmp_model_file.read_bytes())
    (tmp_path / "renamed.safetensors.sig").write_bytes(
        default_sig_path(tmp_model_file).read_bytes()
    )
    result = verify_model(renamed, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "name mismatch"


def _write_v1_sig(model_path, keypair, claimed_name=None):
    """Hand-build a modelsign 1.x signature, whose `file` field is unsigned."""
    import base64
    import time

    from modelsign.crypto.keys import compute_fingerprint, public_key_to_bytes
    from modelsign.crypto.sign import build_file_message, sign_bytes
    from modelsign.formats.single import hash_file
    from modelsign.identity.canonical import canonical_json
    from modelsign.identity.card import ModelCard
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


def test_v2_binds_the_name_into_the_signature(tmp_keypair, tmp_path):
    """Editing the .sig's `file` field must not make a swap verify.

    The earlier check compared sig.file to the real name, but sig.file was
    not covered by the signature, so an attacker simply edited it.
    """
    first = tmp_path / "shard-one.safetensors"
    first.write_bytes(b"shard-one-content")
    sign_model(first, name="Sharded", key=tmp_keypair["private"])

    swapped = tmp_path / "swapped"
    swapped.mkdir()
    victim = swapped / "shard-two.safetensors"
    victim.write_bytes(first.read_bytes())

    sig = read_sig(default_sig_path(first))
    sig.file = "shard-two.safetensors"          # forge the unauthenticated claim
    write_sig(sig, default_sig_path(victim))

    result = verify_model(victim, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "invalid signature"


def test_v2_reports_a_rename_clearly(tmp_keypair, tmp_path):
    original = tmp_path / "model.safetensors"
    original.write_bytes(b"weights")
    sign_model(original, name="Named", key=tmp_keypair["private"])

    moved = tmp_path / "copy"
    moved.mkdir()
    renamed = moved / "renamed.safetensors"
    renamed.write_bytes(original.read_bytes())
    (moved / "renamed.safetensors.sig").write_bytes(
        default_sig_path(original).read_bytes()
    )

    result = verify_model(renamed, pubkey=tmp_keypair["public"])
    assert not result
    assert result.error == "name mismatch"


def test_new_signatures_are_name_bound(tmp_keypair, tmp_model_file):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    result = verify_model(tmp_model_file, pubkey=tmp_keypair["public"])
    assert result.verified
    assert result.name_bound is True


def test_v1_signatures_still_verify_but_are_not_name_bound(tmp_keypair, tmp_model_file):
    _write_v1_sig(tmp_model_file, tmp_keypair)
    result = verify_model(tmp_model_file, pubkey=tmp_keypair["public"])
    assert result.verified
    assert result.name_bound is False


def test_require_name_binding_rejects_a_v1_signature(tmp_keypair, tmp_model_file):
    _write_v1_sig(tmp_model_file, tmp_keypair)
    result = verify_model(
        tmp_model_file, pubkey=tmp_keypair["public"], require_name_binding=True
    )
    assert not result
    assert result.error == "unauthenticated name"


def test_directory_signatures_are_bound_by_their_manifest(tmp_keypair, tmp_model_dir):
    """A snapshot verifies under a different directory name than it was signed as."""
    import shutil

    sign_model(tmp_model_dir, name="Sharded", key=tmp_keypair["private"])
    elsewhere = tmp_model_dir.parent / "snapshot-abc123"
    shutil.copytree(tmp_model_dir, elsewhere)
    shutil.copy(default_sig_path(tmp_model_dir), default_sig_path(elsewhere))

    result = verify_model(elsewhere, pubkey=tmp_keypair["public"])
    assert result.verified
    assert result.name_bound is True
