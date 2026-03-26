"""Tests for ModelCard dataclass and validation."""

import pytest
from modelsign.identity.card import ModelCard, validate_card


def test_minimal_card():
    card = ModelCard(name="my-model")
    assert card.name == "my-model"
    assert card.architecture is None
    assert card.extra == {}


def test_full_card():
    card = ModelCard(
        name="Llama-3.1-8B-Chat-QJ",
        architecture="LlamaForCausalLM",
        base_model="meta-llama/Llama-3.1-8B-Instruct",
        parent_signature="sha256:abc123def456",
        version="1.0.0",
        creator="ConstantQJ",
        contact="qj@constantone.ai",
        license="Llama 3.1 Community",
        intended_use="Chat assistant",
        restrictions="No medical/legal advice",
        training={"dataset": "custom-chat-v2", "dataset_hash": "sha256:def456", "epochs": 3},
        quantization=None,
        eval_metrics={"mmlu": 0.68, "humaneval": 0.53},
        merge_details=None,
        extra={"custom_field": "custom_value"},
    )
    assert card.name == "Llama-3.1-8B-Chat-QJ"
    assert card.eval_metrics["mmlu"] == 0.68


def test_validate_empty_name_fails():
    with pytest.raises(ValueError, match="name"):
        validate_card(ModelCard(name=""))


def test_validate_non_string_name_fails():
    with pytest.raises(ValueError, match="name"):
        validate_card(ModelCard(name=123))


def test_validate_valid_parent_signature():
    card = ModelCard(name="test", parent_signature="sha256:abcdef1234567890")
    validate_card(card)


def test_validate_invalid_parent_signature():
    with pytest.raises(ValueError, match="parent_signature"):
        validate_card(ModelCard(name="test", parent_signature="md5:abc"))


def test_validate_invalid_parent_signature_no_colon():
    with pytest.raises(ValueError, match="parent_signature"):
        validate_card(ModelCard(name="test", parent_signature="just-a-hash"))


def test_validate_dataset_hash():
    card = ModelCard(name="test", training={"dataset_hash": "sha256:abc123"})
    validate_card(card)


def test_validate_invalid_dataset_hash():
    with pytest.raises(ValueError, match="dataset_hash"):
        validate_card(ModelCard(name="test", training={"dataset_hash": "nope"}))


def test_to_dict_excludes_none():
    card = ModelCard(name="test")
    d = card.to_dict()
    assert "name" in d
    assert "architecture" not in d
    assert "extra" not in d or d.get("extra") == {}


def test_to_dict_includes_set_values():
    card = ModelCard(name="test", creator="QJ", eval_metrics={"acc": 0.95})
    d = card.to_dict()
    assert d["name"] == "test"
    assert d["creator"] == "QJ"
    assert d["eval_metrics"]["acc"] == 0.95


def test_from_dict():
    data = {"name": "test", "creator": "QJ", "unknown_field": "preserved"}
    card = ModelCard.from_dict(data)
    assert card.name == "test"
    assert card.creator == "QJ"
    assert card.extra == {"unknown_field": "preserved"}


def test_from_dict_preserves_unknown_fields():
    data = {"name": "test", "future_field": 42, "another": "value"}
    card = ModelCard.from_dict(data)
    assert card.extra == {"future_field": 42, "another": "value"}
