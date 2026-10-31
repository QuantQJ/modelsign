"""Tests for provenance chain verification."""

import json

import pytest

from modelsign.api import default_sig_path, sign_model
from modelsign.lineage import (
    index_signatures,
    sig_digest,
    verify_lineage,
    verify_signature_only,
)
from modelsign.sig import read_sig, write_sig


@pytest.fixture
def chain(tmp_path, tmp_keypair):
    """Three generations: base -> sft -> dpo, with a registry of ancestor sigs."""
    registry = tmp_path / "registry"
    registry.mkdir()

    base = tmp_path / "base.safetensors"
    base.write_bytes(b"base-weights")
    sign_model(base, name="Base", key=tmp_keypair["private"])

    sft = tmp_path / "sft.safetensors"
    sft.write_bytes(b"sft-weights")
    sign_model(sft, name="SFT", key=tmp_keypair["private"], parent=default_sig_path(base))

    dpo = tmp_path / "dpo.safetensors"
    dpo.write_bytes(b"dpo-weights")
    sign_model(dpo, name="DPO", key=tmp_keypair["private"], parent=default_sig_path(sft))

    for model in (base, sft):
        target = registry / (model.name + ".sig")
        target.write_bytes(default_sig_path(model).read_bytes())

    return {"base": base, "sft": sft, "dpo": dpo, "registry": registry}


def test_full_chain_verifies(chain, tmp_keypair):
    result = verify_lineage(
        chain["dpo"],
        search=[chain["registry"]],
        pubkey=tmp_keypair["public"],
        require_complete=True,
    )
    assert result
    assert result.complete is True
    assert [link.name for link in result.chain] == ["DPO", "SFT", "Base"]
    # only the model in hand has its bytes checked; ancestors are signature-only
    assert result.chain[0].bytes_verified is True
    assert all(not link.bytes_verified for link in result.chain[1:])


def test_parent_signature_is_recorded_on_signing(chain):
    sig = read_sig(default_sig_path(chain["dpo"]))
    assert sig.identity["parent_signature"] == sig_digest(default_sig_path(chain["sft"]))


def test_tampered_ancestor_breaks_the_chain(chain, tmp_keypair):
    ancestor = chain["registry"] / "sft.safetensors.sig"
    sig = read_sig(ancestor)
    sig.identity["name"] = "Something-Else"
    write_sig(sig, ancestor)

    result = verify_lineage(
        chain["dpo"], search=[chain["registry"]], pubkey=tmp_keypair["public"]
    )
    # editing the card changes the signature digest, so the link no longer resolves
    assert not result.complete
    assert result.chain[-1].error == "parent signature not found"


def test_forged_ancestor_signature_is_caught(chain, tmp_keypair):
    """A .sig placed at the right digest but with a broken signature fails."""
    ancestor = chain["registry"] / "sft.safetensors.sig"
    sig = read_sig(ancestor)
    original_digest = sig_digest(sig)
    sig.signature = "A" * len(sig.signature)
    write_sig(sig, ancestor)

    index = index_signatures([chain["registry"]])
    index[original_digest] = ancestor  # pretend it still indexes

    import modelsign.lineage as lineage

    original_index = lineage.index_signatures
    lineage.index_signatures = lambda search: index
    try:
        result = verify_lineage(
            chain["dpo"], search=[chain["registry"]], pubkey=tmp_keypair["public"]
        )
    finally:
        lineage.index_signatures = original_index

    assert not result
    assert result.chain[-1].error == "invalid signature"


def test_missing_ancestor_is_an_incomplete_chain_not_a_failure(chain, tmp_keypair):
    (chain["registry"] / "base.safetensors.sig").unlink()
    result = verify_lineage(
        chain["dpo"], search=[chain["registry"]], pubkey=tmp_keypair["public"]
    )
    assert result.verified is True
    assert result.complete is False


def test_require_complete_rejects_a_truncated_chain(chain, tmp_keypair):
    (chain["registry"] / "base.safetensors.sig").unlink()
    result = verify_lineage(
        chain["dpo"],
        search=[chain["registry"]],
        pubkey=tmp_keypair["public"],
        require_complete=True,
    )
    assert not result
    assert "not found" in result.error


def test_tampered_head_model_fails_at_depth_zero(chain, tmp_keypair):
    chain["dpo"].write_bytes(b"swapped-weights")
    result = verify_lineage(
        chain["dpo"], search=[chain["registry"]], pubkey=tmp_keypair["public"]
    )
    assert not result
    assert result.chain[0].error == "hash mismatch"
    assert result.depth == 1


def test_sig_digest_survives_reformatting(chain):
    """The digest is over canonical JSON, so whitespace cannot break a chain."""
    path = chain["registry"] / "sft.safetensors.sig"
    before = sig_digest(path)
    data = json.loads(path.read_text())
    path.write_text(json.dumps(data, indent=7, sort_keys=True))
    assert sig_digest(path) == before


def test_ancestor_verifies_without_its_weights(chain):
    """An ancestor's model file is usually gone; its signature still verifies."""
    chain["sft"].unlink()
    sig = read_sig(chain["registry"] / "sft.safetensors.sig")
    assert verify_signature_only(sig) is True


def test_a_chain_of_one_is_complete(tmp_path, tmp_keypair):
    model = tmp_path / "solo.safetensors"
    model.write_bytes(b"weights")
    sign_model(model, name="Solo", key=tmp_keypair["private"])
    result = verify_lineage(model, pubkey=tmp_keypair["public"], require_complete=True)
    assert result
    assert result.complete is True
    assert result.depth == 1


def test_directory_models_can_be_ancestors(tmp_path, tmp_keypair, tmp_model_dir):
    sign_model(tmp_model_dir, name="Dir-Base", key=tmp_keypair["private"])
    child = tmp_path / "child.safetensors"
    child.write_bytes(b"child-weights")
    sign_model(
        child,
        name="Child",
        key=tmp_keypair["private"],
        parent=default_sig_path(tmp_model_dir),
    )
    result = verify_lineage(
        child,
        search=[default_sig_path(tmp_model_dir)],
        pubkey=tmp_keypair["public"],
        require_complete=True,
    )
    assert result
    assert [link.name for link in result.chain] == ["Child", "Dir-Base"]
