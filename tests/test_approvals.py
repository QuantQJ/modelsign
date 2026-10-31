"""Tests for approval countersignatures."""

import json
import string

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


B64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"


def non_canonical(encoded: str) -> str:
    """Re-encode a 32-byte key's base64 with an unused bit flipped.

    32 bytes encode to 43 data characters plus one "=": the last data
    character carries 4 bits of key and 2 bits that mean nothing, so flipping
    one always yields a different string that decodes to the same key. This is
    computed rather than searched for, so the test can never skip itself.
    """
    index = B64_ALPHABET.index(encoded[-2])
    return encoded[:-2] + B64_ALPHABET[index ^ 1] + "="


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


# -- the chain


def test_removing_an_interior_approval_is_detected(signed, approver, tmp_path):
    """Each approval commits to the bytes of the one before it."""
    second = Ed25519PrivateKey.generate()
    second_priv = tmp_path / "second.pem"
    second_priv.write_bytes(second.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    third = Ed25519PrivateKey.generate()
    third_priv = tmp_path / "third.pem"
    third_priv.write_bytes(third.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    approve(signed, key=approver["private"], role="build")
    approve(signed, key=second_priv, role="security-review")
    approve(signed, key=third_priv, role="release-manager")

    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    del data["approvals"][1]          # drop the middle one
    sig_path.write_text(json.dumps(data))

    approvals = read_approvals(sig_path)
    assert approvals[0].chain_ok is True
    assert approvals[1].chain_ok is False
    assert approvals[1].error is not None


def test_reordering_approvals_is_detected(signed, approver, tmp_path):
    second = Ed25519PrivateKey.generate()
    second_priv = tmp_path / "second.pem"
    second_priv.write_bytes(second.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    approve(signed, key=approver["private"], role="build")
    approve(signed, key=second_priv, role="release-manager")

    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    data["approvals"].reverse()
    sig_path.write_text(json.dumps(data))

    approvals = read_approvals(sig_path)
    assert not all(a.chain_ok for a in approvals)


def test_a_trailing_removal_is_still_invisible(signed, approver, tmp_path):
    """The documented irreducible gap, asserted so it cannot be forgotten."""
    approve(signed, key=approver["private"], role="build")
    approve(signed, key=approver["private"], role="release-manager")

    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    data["approvals"] = data["approvals"][:1]      # drop the last
    sig_path.write_text(json.dumps(data))

    approvals = read_approvals(sig_path, pubkeys=[approver["public"]])
    assert len(approvals) == 1
    assert approvals[0].ok is True        # nothing inside the file betrays it
    with pytest.raises(ApprovalError):   # which is why policy has to ask
        require_approval(
            sig_path, roles=["release-manager"], pubkeys=[approver["public"]]
        )


def test_an_inserted_approval_breaks_the_chain(signed, approver, tmp_path):
    approve(signed, key=approver["private"], role="build")
    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    forged = dict(data["approvals"][0])
    forged["role"] = "release-manager"
    data["approvals"].append(forged)
    sig_path.write_text(json.dumps(data))

    approvals = read_approvals(sig_path, pubkeys=[approver["public"]])
    assert approvals[1].ok is False


# -- trust must not rest on a 32-bit fingerprint


def test_trust_is_decided_on_the_whole_key_not_the_fingerprint(
    signed, approver, tmp_path, monkeypatch
):
    """Collide the 32-bit display fingerprint and trust must not follow it."""
    import modelsign.approvals as approvals_mod

    attacker = Ed25519PrivateKey.generate()
    attacker_priv = tmp_path / "attacker.pem"
    attacker_priv.write_bytes(attacker.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    # Force every key to share a fingerprint, which is what grinding 32 bits
    # buys an attacker for a few minutes of compute.
    monkeypatch.setattr(approvals_mod, "compute_fingerprint", lambda key: "ed25519:collide")

    approve(signed, key=attacker_priv, role="release-manager")
    result = read_approvals(default_sig_path(signed), pubkeys=[approver["public"]])
    assert result[0].valid is True       # the attacker signed their own record
    assert result[0].trusted is False    # but it is not a key we hold
    with pytest.raises(ApprovalError):
        require_approval(
            default_sig_path(signed),
            roles=["release-manager"],
            pubkeys=[approver["public"]],
        )


# -- policy


def test_every_required_role_must_be_satisfied(signed, approver, tmp_path):
    approve(signed, key=approver["private"], role="release-manager")
    with pytest.raises(ApprovalError) as excinfo:
        require_approval(
            default_sig_path(signed),
            roles=["release-manager", "security-review"],
            pubkeys=[approver["public"]],
        )
    assert "security-review" in str(excinfo.value)


def test_a_quorum_counts_distinct_approvers(signed, approver):
    """One person wearing two hats is one approver."""
    approve(signed, key=approver["private"], role="build")
    approve(signed, key=approver["private"], role="release-manager")

    assert len(
        require_approval(
            default_sig_path(signed), count=1, pubkeys=[approver["public"]]
        )
    ) == 2
    with pytest.raises(ApprovalError) as excinfo:
        require_approval(
            default_sig_path(signed), count=2, pubkeys=[approver["public"]]
        )
    assert "distinct" in str(excinfo.value)


# -- one key is one approver, however it is encoded


def test_one_key_cannot_pad_a_quorum_with_re_encodings(signed, approver, tmp_path):
    """base64 leaves unused bits, so one key has four encodings.

    Counting distinct approvers on the encoded string would let a single
    approver satisfy a four-person quorum.
    """
    import base64

    approve(signed, key=approver["private"], role="build")
    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    record = data["approvals"][0]
    canonical = record["public_key"]
    variant = non_canonical(canonical)
    assert variant != canonical
    assert base64.b64decode(variant, validate=True) == base64.b64decode(canonical)

    for position in (1, 2, 3):
        clone = dict(record)
        clone["public_key"] = variant
        clone["role"] = f"role-{position}"
        data["approvals"].append(clone)
    sig_path.write_text(json.dumps(data))

    approvals = read_approvals(sig_path, pubkeys=[approver["public"]])
    # the re-encoded clones are refused outright
    assert all(not a.valid for a in approvals[1:])
    with pytest.raises(ApprovalError):
        require_approval(sig_path, count=2, pubkeys=[approver["public"]])


def test_a_non_canonical_key_encoding_is_refused(signed, approver):
    approve(signed, key=approver["private"], role="build")
    sig_path = default_sig_path(signed)
    data = json.loads(sig_path.read_text())
    data["approvals"][0]["public_key"] = non_canonical(
        data["approvals"][0]["public_key"]
    )
    sig_path.write_text(json.dumps(data))
    assert read_approvals(sig_path, pubkeys=[approver["public"]])[0].valid is False


def test_approvers_can_be_pinned_by_key(signed, approver, tmp_path):
    other = Ed25519PrivateKey.generate()
    other_priv = tmp_path / "other.pem"
    other_pub = tmp_path / "other_pub.pem"
    other_priv.write_bytes(other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    other_pub.write_bytes(other.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    approve(signed, key=other_priv, role="release-manager")
    trusted = [approver["public"], other_pub]

    assert require_approval(
        default_sig_path(signed), keys=[other_pub], pubkeys=trusted
    )
    with pytest.raises(ApprovalError):
        require_approval(
            default_sig_path(signed), keys=[approver["public"]], pubkeys=trusted
        )


def test_pinning_by_display_fingerprint_is_refused(signed, approver):
    approve(signed, key=approver["private"], role="build")
    with pytest.raises(ApprovalError) as excinfo:
        require_approval(
            default_sig_path(signed),
            keys=["ed25519:deadbeef"],
            pubkeys=[approver["public"]],
        )
    assert "not an identity" in str(excinfo.value)
