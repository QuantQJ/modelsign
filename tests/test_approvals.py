"""Tests for approval countersignatures."""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modelsign.api import default_sig_path, sign_model
from modelsign.approvals import (
    ApprovalError,
    approve,
    read_approvals,
    require_approval,
)
from modelsign.sig import read_sig, write_sig


@pytest.fixture
def approver(tmp_path):
    key = Ed25519PrivateKey.generate()
    priv, pub = tmp_path / "rm_priv.pem", tmp_path / "rm_pub.pem"
    priv.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return {"private": priv, "public": pub}


@pytest.fixture
def signed(tmp_path, tmp_keypair):
    model = tmp_path / "model.safetensors"
    model.write_bytes(b"weights")
    sign_model(model, name="Release-Candidate", key=tmp_keypair["private"])
    return model


def test_approve_appends_a_verifiable_approval(signed, approver):
    approve(signed, key=approver["private"], role="release-manager", approver="J. Kerr")
    approvals = read_approvals(
        default_sig_path(signed), pubkeys=[approver["public"]]
    )
    assert len(approvals) == 1
    assert approvals[0].role == "release-manager"
    assert approvals[0].approver == "J. Kerr"
    assert approvals[0].ok is True


def test_an_approval_from_an_unknown_key_is_valid_but_not_trusted(signed, approver):
    approve(signed, key=approver["private"], role="release-manager")
    approvals = read_approvals(default_sig_path(signed))
    assert approvals[0].valid is True
    assert approvals[0].trusted is False
    assert approvals[0].ok is False


def test_require_approval_needs_a_trusted_key(signed, approver):
    approve(signed, key=approver["private"], role="release-manager")
    with pytest.raises(ApprovalError) as excinfo:
        require_approval(default_sig_path(signed), roles=["release-manager"])
    assert "1 approval(s) present" in str(excinfo.value)

    assert require_approval(
        default_sig_path(signed),
        roles=["release-manager"],
        pubkeys=[approver["public"]],
    )


def test_require_approval_checks_the_role(signed, approver):
    approve(signed, key=approver["private"], role="release-manager")
    with pytest.raises(ApprovalError):
        require_approval(
            default_sig_path(signed),
            roles=["security-review"],
            pubkeys=[approver["public"]],
        )


def test_editing_an_approval_invalidates_it(signed, approver):
    approve(signed, key=approver["private"], role="release-manager")
    sig_path = default_sig_path(signed)
    sig = read_sig(sig_path)
    sig.approvals[0]["role"] = "security-review"
    write_sig(sig, sig_path)

    approvals = read_approvals(sig_path, pubkeys=[approver["public"]])
    assert approvals[0].valid is False


def test_an_approval_cannot_be_moved_to_another_model(
    signed, approver, tmp_path, tmp_keypair
):
    """It is signed over the digest of one specific signature."""
    approve(signed, key=approver["private"], role="release-manager")
    stolen = read_sig(default_sig_path(signed)).approvals

    other = tmp_path / "other.safetensors"
    other.write_bytes(b"other-weights")
    sign_model(other, name="Other", key=tmp_keypair["private"])
    other_sig_path = default_sig_path(other)
    other_sig = read_sig(other_sig_path)
    other_sig.approvals = stolen
    write_sig(other_sig, other_sig_path)

    approvals = read_approvals(other_sig_path, pubkeys=[approver["public"]])
    assert approvals[0].valid is False


def test_the_same_key_cannot_approve_the_same_role_twice(signed, approver):
    approve(signed, key=approver["private"], role="release-manager")
    with pytest.raises(ApprovalError):
        approve(signed, key=approver["private"], role="release-manager")


def test_two_approvers_can_both_sign_off(signed, approver, tmp_path):
    second = Ed25519PrivateKey.generate()
    second_priv = tmp_path / "second.pem"
    second_pub = tmp_path / "second_pub.pem"
    second_priv.write_bytes(second.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    second_pub.write_bytes(second.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    approve(signed, key=approver["private"], role="release-manager")
    approve(signed, key=second_priv, role="security-review")

    assert len(
        require_approval(
            default_sig_path(signed),
            count=2,
            pubkeys=[approver["public"], second_pub],
        )
    ) == 2


def test_an_approval_needs_a_role(signed, approver):
    with pytest.raises(ApprovalError):
        approve(signed, key=approver["private"], role="   ")


def test_approving_an_unsigned_model_fails(tmp_path, approver):
    model = tmp_path / "unsigned.safetensors"
    model.write_bytes(b"weights")
    with pytest.raises(ApprovalError):
        approve(model, key=approver["private"], role="release-manager")


def test_the_model_signature_still_verifies_after_an_approval(
    signed, approver, tmp_keypair
):
    """Approvals are appended, so they must not disturb the model's signature."""
    from modelsign.api import verify_model

    approve(signed, key=approver["private"], role="release-manager")
    assert verify_model(signed, pubkey=tmp_keypair["public"])


def test_a_removed_approval_leaves_no_trace(signed, approver, tmp_keypair):
    """Documented limitation: presence must be required, never inferred."""
    from modelsign.api import verify_model

    approve(signed, key=approver["private"], role="release-manager")
    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    del data["approvals"]
    sig_path.write_text(json.dumps(data))

    # The model still verifies — which is exactly why a verifier that cares
    # has to ask for the approval rather than trust what it happens to see.
    assert verify_model(signed, pubkey=tmp_keypair["public"])
    with pytest.raises(ApprovalError):
        require_approval(sig_path, roles=["release-manager"], pubkeys=[approver["public"]])
