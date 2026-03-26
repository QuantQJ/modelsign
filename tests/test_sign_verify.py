"""Tests for Ed25519 sign and verify operations."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from modelsign.crypto.sign import sign_bytes, build_file_message, build_dir_message
from modelsign.crypto.verify import verify_bytes
from modelsign.crypto.keys import load_private_key, load_public_key


def test_sign_verify_roundtrip(tmp_keypair):
    private_key = load_private_key(tmp_keypair["private"])
    public_key = load_public_key(tmp_keypair["public"])
    message = b"test message"

    signature = sign_bytes(message, private_key)
    assert isinstance(signature, bytes)
    assert len(signature) == 64

    assert verify_bytes(message, signature, public_key) is True


def test_verify_wrong_message(tmp_keypair):
    private_key = load_private_key(tmp_keypair["private"])
    public_key = load_public_key(tmp_keypair["public"])

    signature = sign_bytes(b"original", private_key)
    assert verify_bytes(b"tampered", signature, public_key) is False


def test_verify_wrong_key(tmp_keypair, tmp_path):
    private_key = load_private_key(tmp_keypair["private"])
    other_key = Ed25519PrivateKey.generate()
    other_public = other_key.public_key()

    signature = sign_bytes(b"message", private_key)
    assert verify_bytes(b"message", signature, other_public) is False


def test_build_file_message():
    file_hash = "a" * 64
    identity_bytes = b'{"name":"test"}'
    msg = build_file_message(file_hash, identity_bytes)
    assert msg == b"modelsign-v1:" + b"a" * 64 + b":" + b'{"name":"test"}'


def test_build_file_message_hash_length():
    identity_bytes = b'{"name":"test"}'
    msg = build_file_message("b" * 64, identity_bytes)
    parts = msg.split(b":", 2)
    assert parts[0] == b"modelsign-v1"
    assert len(parts[1]) == 64
    assert parts[2] == identity_bytes


def test_build_dir_message():
    manifest_hash = "c" * 64
    identity_bytes = b'{"name":"test"}'
    msg = build_dir_message(manifest_hash, identity_bytes)
    assert msg == b"modelsign-v1:dir:" + b"c" * 64 + b":" + b'{"name":"test"}'
