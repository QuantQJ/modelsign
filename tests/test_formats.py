"""Tests for file and directory hashing."""

import hashlib
import pytest
from modelsign.formats.single import hash_file
from modelsign.formats.directory import hash_directory


def test_hash_file(tmp_model_file):
    result = hash_file(tmp_model_file)
    assert isinstance(result, str)
    assert len(result) == 64


def test_hash_file_matches_hashlib(tmp_model_file):
    result = hash_file(tmp_model_file)
    expected = hashlib.sha256(tmp_model_file.read_bytes()).hexdigest()
    assert result == expected


def test_hash_file_deterministic(tmp_model_file):
    assert hash_file(tmp_model_file) == hash_file(tmp_model_file)


def test_hash_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "nonexistent.bin")


def test_hash_directory(tmp_model_dir):
    manifest, manifest_hash = hash_directory(tmp_model_dir)
    assert isinstance(manifest, dict)
    assert "files" in manifest
    assert len(manifest["files"]) == 3
    assert isinstance(manifest_hash, str)
    assert len(manifest_hash) == 64


def test_hash_directory_sorted_keys(tmp_model_dir):
    manifest, _ = hash_directory(tmp_model_dir)
    keys = list(manifest["files"].keys())
    assert keys == sorted(keys, key=lambda p: p.encode("utf-8"))


def test_hash_directory_deterministic(tmp_model_dir):
    _, hash1 = hash_directory(tmp_model_dir)
    _, hash2 = hash_directory(tmp_model_dir)
    assert hash1 == hash2


def test_hash_directory_detects_change(tmp_model_dir):
    _, hash1 = hash_directory(tmp_model_dir)
    (tmp_model_dir / "config.json").write_bytes(b'{"model_type": "gpt"}')
    _, hash2 = hash_directory(tmp_model_dir)
    assert hash1 != hash2


def test_hash_directory_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_directory(tmp_path / "nonexistent_dir")
