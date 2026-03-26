"""Tests for key generation, loading, fingerprint, and keyring."""

import os
import pytest
from modelsign.crypto.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    compute_fingerprint,
    keyring_add,
    keyring_list,
    keyring_remove,
    public_key_to_bytes,
)


def test_generate_keypair(tmp_path):
    priv_path, pub_path = generate_keypair(tmp_path)
    assert priv_path.exists()
    assert pub_path.exists()
    assert oct(priv_path.stat().st_mode & 0o777) == "0o600"


def test_generate_keypair_idempotent(tmp_path):
    priv1, pub1 = generate_keypair(tmp_path)
    priv2, pub2 = generate_keypair(tmp_path)
    assert priv1.read_bytes() == priv2.read_bytes()


def test_load_private_key(tmp_keypair):
    key = load_private_key(tmp_keypair["private"])
    assert key is not None


def test_load_public_key(tmp_keypair):
    key = load_public_key(tmp_keypair["public"])
    assert key is not None


def test_compute_fingerprint(tmp_keypair):
    key = load_public_key(tmp_keypair["public"])
    fp = compute_fingerprint(key)
    assert fp.startswith("ed25519:")
    hex_part = fp.split(":")[1]
    assert len(hex_part) == 8
    assert all(c in "0123456789abcdef" for c in hex_part)


def test_fingerprint_deterministic(tmp_keypair):
    key = load_public_key(tmp_keypair["public"])
    assert compute_fingerprint(key) == compute_fingerprint(key)


def test_keyring_add_list_remove(tmp_path):
    keyring_dir = tmp_path / "trusted_keys"
    keyring_dir.mkdir()

    _, pub_path = generate_keypair(tmp_path / "keys")

    keyring_add(keyring_dir, pub_path, alias="testkey")
    keys = keyring_list(keyring_dir)
    assert len(keys) == 1
    assert keys[0]["alias"] == "testkey"

    keyring_remove(keyring_dir, "testkey")
    keys = keyring_list(keyring_dir)
    assert len(keys) == 0


def test_public_key_to_bytes(tmp_keypair):
    key = load_public_key(tmp_keypair["public"])
    raw = public_key_to_bytes(key)
    assert isinstance(raw, bytes)
    assert len(raw) == 32
