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


def test_parallel_hashing_matches_serial_exactly(tmp_path):
    """Concurrency must not change the manifest, or every signature breaks."""
    from modelsign.formats.directory import hash_directory

    model = tmp_path / "model"
    model.mkdir()
    (model / "sub").mkdir()
    for i in range(12):
        (model / f"shard-{i:05d}.safetensors").write_bytes(f"weights-{i}".encode() * 64)
    (model / "sub" / "nested.json").write_bytes(b'{"a":1}')
    (model / "config.json").write_bytes(b'{"model_type":"llama"}')

    serial_manifest, serial_hash = hash_directory(model, max_workers=1)
    parallel_manifest, parallel_hash = hash_directory(model, max_workers=8)

    assert parallel_manifest == serial_manifest
    assert parallel_hash == serial_hash
    # and the order in the manifest is the sorted order, not completion order
    assert list(parallel_manifest["files"]) == sorted(serial_manifest["files"])


def test_parallel_hashing_is_stable_across_runs(tmp_path):
    from modelsign.formats.directory import hash_directory

    model = tmp_path / "model"
    model.mkdir()
    for i in range(8):
        (model / f"f{i}.bin").write_bytes(bytes([i]) * 1024)

    hashes = {hash_directory(model)[1] for _ in range(5)}
    assert len(hashes) == 1
