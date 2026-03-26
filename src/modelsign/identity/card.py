"""Model Identity Card — structured, signed metadata about a model."""

import re
from dataclasses import dataclass, field, fields
from typing import Optional

_HASH_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]+$")


@dataclass
class ModelCard:
    """Structured identity metadata for a signed model.

    Only `name` is required. All other fields are optional.
    Unknown fields from JSON are preserved in `extra` for forward compatibility.
    """

    name: str = ""
    architecture: Optional[str] = None
    base_model: Optional[str] = None
    parent_signature: Optional[str] = None
    version: Optional[str] = None
    creator: Optional[str] = None
    contact: Optional[str] = None
    license: Optional[str] = None
    intended_use: Optional[str] = None
    restrictions: Optional[str] = None
    training: Optional[dict] = None
    quantization: Optional[str] = None
    eval_metrics: Optional[dict] = None
    merge_details: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dict, excluding None values and empty extra."""
        result = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if f.name == "extra":
                if val:
                    result.update(val)
            elif val is not None:
                result[f.name] = val
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ModelCard":
        """Create from dict, preserving unknown fields in extra."""
        known = {f.name for f in fields(cls)} - {"extra"}
        known_data = {k: v for k, v in data.items() if k in known}
        unknown_data = {k: v for k, v in data.items() if k not in known}
        return cls(**known_data, extra=unknown_data)


def validate_card(card: ModelCard) -> None:
    """Validate a ModelCard. Raises ValueError on invalid fields."""
    if not isinstance(card.name, str) or not card.name.strip():
        raise ValueError("name must be a non-empty string")

    if card.parent_signature is not None:
        if not _HASH_PATTERN.match(card.parent_signature):
            raise ValueError(
                f"parent_signature must match 'sha256:<hex>', got: {card.parent_signature}"
            )

    if card.training and "dataset_hash" in card.training:
        dh = card.training["dataset_hash"]
        if not _HASH_PATTERN.match(dh):
            raise ValueError(
                f"training.dataset_hash must match 'sha256:<hex>', got: {dh}"
            )
