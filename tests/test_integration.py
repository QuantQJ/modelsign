"""Integration tests: full sign → verify round-trip."""

import base64
from pathlib import Path

from modelsign.crypto.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    compute_fingerprint,
    public_key_to_bytes,
)
from modelsign.crypto.sign import sign_bytes, build_file_message, build_dir_message
from modelsign.crypto.verify import verify_bytes
from modelsign.identity.card import ModelCard, validate_card
from modelsign.identity.canonical import canonical_json
from modelsign.formats.single import hash_file
from modelsign.formats.directory import hash_directory
from modelsign.sig import SigFile, write_sig, read_sig


def _sign_model(model_path, key_dir, card_dict):
    """Full sign workflow for a single file."""
    priv_path, pub_path = generate_keypair(key_dir)
    private_key = load_private_key(priv_path)
    public_key = load_public_key(pub_path)

    card = ModelCard.from_dict(card_dict)
    validate_card(card)
    identity_dict = card.to_dict()
    identity_bytes = canonical_json(identity_dict)

    file_hash = hash_file(model_path)
    message = build_file_message(file_hash, identity_bytes)
    signature = sign_bytes(message, private_key)

    raw_pub = public_key_to_bytes(public_key)
    sig = SigFile(
        modelsign_version="1.0",
        file=Path(model_path).name,
        sha256=file_hash,
        signature=base64.b64encode(signature).decode(),
        algorithm="ed25519",
        signed_at="2026-03-25T14:30:00Z",
        public_key=base64.b64encode(raw_pub).decode(),
        key_fingerprint=compute_fingerprint(public_key),
        identity=identity_dict,
    )

    sig_path = Path(str(model_path) + ".sig")
    write_sig(sig, sig_path)
    return sig_path


def _verify_model(model_path, sig_path, pub_path):
    """Full verify workflow for a single file."""
    sig = read_sig(sig_path)
    public_key = load_public_key(pub_path)

    file_hash = hash_file(model_path)
    if file_hash != sig.sha256:
        return False, "hash mismatch"

    identity_bytes = canonical_json(sig.identity)
    message = build_file_message(file_hash, identity_bytes)
    signature = base64.b64decode(sig.signature)

    if not verify_bytes(message, signature, public_key):
        return False, "invalid signature"

    return True, "verified"


def test_full_sign_verify_roundtrip(tmp_model_file, tmp_path):
    key_dir = tmp_path / "keys"
    sig_path = _sign_model(
        tmp_model_file, key_dir, {"name": "test-model", "creator": "QJ"}
    )
    pub_path = key_dir / "public.pem"
    ok, msg = _verify_model(tmp_model_file, sig_path, pub_path)
    assert ok is True
    assert msg == "verified"


def test_detect_tampered_file(tmp_model_file, tmp_path):
    key_dir = tmp_path / "keys"
    sig_path = _sign_model(tmp_model_file, key_dir, {"name": "test-model"})

    tmp_model_file.write_bytes(b"tampered-weights")

    pub_path = key_dir / "public.pem"
    ok, msg = _verify_model(tmp_model_file, sig_path, pub_path)
    assert ok is False
    assert msg == "hash mismatch"


def test_detect_identity_swap(tmp_model_file, tmp_path):
    key_dir = tmp_path / "keys"
    sig_path = _sign_model(tmp_model_file, key_dir, {"name": "original"})

    import json
    sig_data = json.loads(sig_path.read_text())
    sig_data["identity"]["name"] = "swapped-model"
    sig_path.write_text(json.dumps(sig_data, indent=2))

    pub_path = key_dir / "public.pem"
    ok, msg = _verify_model(tmp_model_file, sig_path, pub_path)
    assert ok is False
    assert msg == "invalid signature"


def test_full_directory_sign_verify(tmp_model_dir, tmp_path):
    key_dir = tmp_path / "keys"
    priv_path, pub_path = generate_keypair(key_dir)
    private_key = load_private_key(priv_path)
    public_key = load_public_key(pub_path)

    card = ModelCard(name="sharded-model")
    validate_card(card)
    identity_dict = card.to_dict()
    identity_bytes = canonical_json(identity_dict)

    manifest, manifest_hash = hash_directory(tmp_model_dir)
    message = build_dir_message(manifest_hash, identity_bytes)
    signature = sign_bytes(message, private_key)

    raw_pub = public_key_to_bytes(public_key)
    sig = SigFile(
        modelsign_version="1.0",
        file=tmp_model_dir.name,
        sha256=manifest_hash,
        signature=base64.b64encode(signature).decode(),
        algorithm="ed25519",
        signed_at="2026-03-25T14:30:00Z",
        public_key=base64.b64encode(raw_pub).decode(),
        key_fingerprint=compute_fingerprint(public_key),
        identity=identity_dict,
        manifest=manifest,
    )

    sig_path = tmp_path / "model_dir.sig"
    write_sig(sig, sig_path)

    loaded = read_sig(sig_path)
    _, verify_hash = hash_directory(tmp_model_dir)
    assert verify_hash == loaded.sha256

    verify_identity_bytes = canonical_json(loaded.identity)
    verify_message = build_dir_message(verify_hash, verify_identity_bytes)
    verify_sig = base64.b64decode(loaded.signature)
    assert verify_bytes(verify_message, verify_sig, public_key) is True
