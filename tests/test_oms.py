"""Tests for OpenSSF Model Signing interoperability.

The golden constants below were captured from a bundle produced by the real
``model-signing`` package (v1.x, ``sign key``). They pin our hashing and
encoding to theirs, so a drift in either breaks a test rather than a user.
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from modelsign import oms

# Captured from model-signing's own output over the two files below.
GOLDEN_CONFIG = b'{"model_type":"llama"}\n'
GOLDEN_WEIGHTS = b"fake-weights-aaa\n"
GOLDEN_CONFIG_DIGEST = "013e93c1cc397541961e670f84ea0d42784536cab4e9d3c5d5b13589f53ab684"
GOLDEN_WEIGHTS_DIGEST = "7eba2d5641b3ef7c938afd442f9faf7d2e730020651b81b444b5179a448a1f94"
GOLDEN_SUBJECT_DIGEST = "ff0a6d47c3cdb1f5ccf6d3769a0152a52f319ac75005b5ab34a067dfbd676a19"


@pytest.fixture
def ec_keypair(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    priv = tmp_path / "ec_priv.pem"
    pub = tmp_path / "ec_pub.pem"
    priv.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return {"private": priv, "public": pub, "key": key}


@pytest.fixture
def golden_model(tmp_path):
    """The exact directory the golden digests were captured from."""
    model = tmp_path / "model"
    model.mkdir()
    (model / "config.json").write_bytes(GOLDEN_CONFIG)
    (model / "model.safetensors").write_bytes(GOLDEN_WEIGHTS)
    return model


# -- format primitives match theirs -------------------------------------


def test_file_digests_match_model_signing(golden_model):
    resources = oms.collect_resources(golden_model)
    assert [r.name for r in resources] == ["config.json", "model.safetensors"]
    assert resources[0].digest == GOLDEN_CONFIG_DIGEST
    assert resources[1].digest == GOLDEN_WEIGHTS_DIGEST


def test_subject_digest_matches_model_signing():
    assert (
        oms.manifest_digest([GOLDEN_CONFIG_DIGEST, GOLDEN_WEIGHTS_DIGEST])
        == GOLDEN_SUBJECT_DIGEST
    )


def test_pae_follows_the_dsse_protocol():
    assert oms.pae(b"xy") == b"DSSEv1 28 application/vnd.in-toto+json 2 xy"


def test_pae_compat_reproduces_the_0_2_0_bug():
    # The old implementation interpolated bytes into a string.
    assert oms.pae_compat(b"xy") == b"DSSEV1 28 application/vnd.in-toto+json 2 b'xy'"


def test_key_hint_is_sha256_of_the_public_pem(ec_keypair):
    import hashlib

    pem = ec_keypair["public"].read_bytes()
    assert oms.key_hint(ec_keypair["key"].public_key()) == hashlib.sha256(pem).hexdigest()


# -- export -------------------------------------------------------------


def test_exported_bundle_has_the_sigstore_shape(golden_model, ec_keypair):
    bundle = oms.export_bundle(golden_model, key=ec_keypair["private"], write=False)
    assert bundle["mediaType"] == oms.BUNDLE_MEDIA_TYPE
    envelope = bundle["dsseEnvelope"]
    assert envelope["payloadType"] == oms.PAYLOAD_TYPE
    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["_type"] == oms.STATEMENT_TYPE
    assert statement["predicateType"] == oms.PREDICATE_TYPE
    assert statement["subject"][0]["digest"]["sha256"] == GOLDEN_SUBJECT_DIGEST
    assert statement["predicate"]["serialization"]["method"] == "files"


def test_export_refuses_an_ed25519_key(golden_model, tmp_path):
    priv = tmp_path / "ed.pem"
    priv.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(oms.OMSError) as excinfo:
        oms.export_bundle(golden_model, key=priv, write=False)
    assert "ECDSA" in str(excinfo.value)


def test_export_writes_model_sig_by_default(golden_model, ec_keypair):
    oms.export_bundle(golden_model, key=ec_keypair["private"])
    assert (golden_model.parent / oms.DEFAULT_BUNDLE_NAME).exists()


def test_git_paths_are_excluded_like_model_signing(golden_model, ec_keypair):
    (golden_model / ".gitattributes").write_bytes(b"* filter=lfs\n")
    bundle = oms.export_bundle(golden_model, key=ec_keypair["private"], write=False)
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    names = [r["name"] for r in statement["predicate"]["resources"]]
    assert ".gitattributes" not in names
    # and the exclusion is recorded so a verifier applies the same rule
    assert ".gitattributes" in statement["predicate"]["serialization"]["ignore_paths"]


# -- verify -------------------------------------------------------------


def test_roundtrip(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert result
    assert result.identity == {"name": "model", "format": "oms"}
    assert result.sha256 == f"sha256:{GOLDEN_SUBJECT_DIGEST}"


def test_modified_file_fails(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    (golden_model / "model.safetensors").write_bytes(b"swapped")
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "hash mismatch"


def test_removed_file_fails(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    (golden_model / "config.json").unlink()
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "missing file"


def test_added_file_fails_closed(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    (golden_model / "smuggled.pkl").write_bytes(b"not in the manifest")
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "unsigned files"
    assert "smuggled.pkl" in result.detail


def test_wrong_key_is_caught_by_the_hint(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    other = tmp_path / "other_pub.pem"
    other.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=other)
    assert not result
    assert result.error == "wrong key"


def test_tampered_payload_fails(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    bundle = oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    statement["subject"][0]["name"] = "someone-elses-model"
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(statement, indent=2).encode()
    ).decode()
    bundle_path.write_text(json.dumps(bundle))
    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "invalid signature"


def test_foreign_media_type_is_rejected(golden_model, ec_keypair, tmp_path):
    bundle_path = tmp_path / "model.sig"
    bundle = oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    bundle["mediaType"] = "application/vnd.example.other+json"
    bundle_path.write_text(json.dumps(bundle))
    with pytest.raises(oms.OMSError):
        oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])


def test_single_file_roundtrip(tmp_keypair, tmp_model_file, ec_keypair, tmp_path):
    bundle_path = tmp_path / "file.sig"
    oms.export_bundle(tmp_model_file, key=ec_keypair["private"], out=bundle_path)
    assert oms.verify_bundle(tmp_model_file, bundle_path, pubkey=ec_keypair["public"])


def test_keygen_writes_a_p256_pair(tmp_path):
    priv, pub = oms.generate_ec_keypair(tmp_path / "keys")
    assert priv.exists() and pub.exists()
    key = oms.load_ec_private_key(priv)
    assert isinstance(key.curve, ec.SECP256R1)
    assert oms.generate_ec_keypair(tmp_path / "keys") == (priv, pub)


def test_symlinked_extra_file_is_caught(golden_model, ec_keypair, tmp_path):
    """A Hugging Face cache is all symlinks, so symlinks must still be counted."""
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)

    payload = tmp_path / "payload.pkl"
    payload.write_bytes(b"attacker-controlled")
    (golden_model / "smuggled.pkl").symlink_to(payload)

    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "unsigned files"
    assert "smuggled.pkl" in result.detail


def test_symlinked_signed_files_still_verify(tmp_path, ec_keypair):
    """The hf cache layout: every entry is a symlink into a blobs dir."""
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    (blobs / "a").write_bytes(GOLDEN_CONFIG)
    (blobs / "b").write_bytes(GOLDEN_WEIGHTS)

    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "config.json").symlink_to(blobs / "a")
    (snapshot / "model.safetensors").symlink_to(blobs / "b")

    bundle = tmp_path / "model.sig"
    oms.export_bundle(
        snapshot, key=ec_keypair["private"], out=bundle, allow_symlinks=True
    )
    assert oms.verify_bundle(snapshot, bundle, pubkey=ec_keypair["public"])


def test_nested_gitignore_is_not_exempt(golden_model, ec_keypair, tmp_path):
    """Only the ignore list's own paths are exempt, not same-named files deeper."""
    bundle_path = tmp_path / "model.sig"
    oms.export_bundle(golden_model, key=ec_keypair["private"], out=bundle_path)
    nested = golden_model / "sub"
    nested.mkdir()
    (nested / ".gitignore").write_bytes(b"payload")

    result = oms.verify_bundle(golden_model, bundle_path, pubkey=ec_keypair["public"])
    assert not result
    assert result.error == "unsigned files"
