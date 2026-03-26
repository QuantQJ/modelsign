"""Tests for .sig file I/O and version migration."""

import json
import pytest
from modelsign.sig import SigFile, write_sig, read_sig, SigVersionError


def _make_sig_data():
    return SigFile(
        modelsign_version="1.0",
        file="model.safetensors",
        sha256="a" * 64,
        signature="dGVzdA==",
        algorithm="ed25519",
        signed_at="2026-03-25T14:30:00Z",
        public_key="cHVia2V5",
        key_fingerprint="ed25519:7f8a3b2c",
        identity={"name": "test-model"},
    )


def test_write_read_roundtrip(tmp_path):
    sig = _make_sig_data()
    sig_path = tmp_path / "model.safetensors.sig"
    write_sig(sig, sig_path)
    loaded = read_sig(sig_path)
    assert loaded.modelsign_version == "1.0"
    assert loaded.file == "model.safetensors"
    assert loaded.sha256 == "a" * 64
    assert loaded.identity["name"] == "test-model"


def test_sig_file_is_valid_json(tmp_path):
    sig = _make_sig_data()
    sig_path = tmp_path / "test.sig"
    write_sig(sig, sig_path)
    data = json.loads(sig_path.read_text())
    assert data["modelsign_version"] == "1.0"


def test_read_sig_minor_version_warns(tmp_path, capsys):
    sig_path = tmp_path / "test.sig"
    data = {
        "modelsign_version": "1.1",
        "file": "m.bin", "sha256": "a" * 64,
        "signature": "sig", "algorithm": "ed25519",
        "signed_at": "2026-01-01T00:00:00Z",
        "public_key": "pk", "key_fingerprint": "ed25519:00000000",
        "identity": {"name": "test"},
    }
    sig_path.write_text(json.dumps(data))
    sig = read_sig(sig_path)
    assert sig.modelsign_version == "1.1"
    captured = capsys.readouterr()
    assert "newer" in captured.err.lower() or "unrecognized" in captured.err.lower()


def test_read_sig_major_version_errors(tmp_path):
    sig_path = tmp_path / "test.sig"
    data = {
        "modelsign_version": "2.0",
        "file": "m.bin", "sha256": "a" * 64,
        "signature": "sig", "algorithm": "ed25519",
        "signed_at": "2026-01-01T00:00:00Z",
        "public_key": "pk", "key_fingerprint": "ed25519:00000000",
        "identity": {"name": "test"},
    }
    sig_path.write_text(json.dumps(data))
    with pytest.raises(SigVersionError, match="v2"):
        read_sig(sig_path)


def test_read_sig_missing_version(tmp_path):
    sig_path = tmp_path / "test.sig"
    sig_path.write_text(json.dumps({"file": "m.bin"}))
    with pytest.raises(SigVersionError, match="invalid"):
        read_sig(sig_path)


def test_read_sig_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_sig(tmp_path / "nonexistent.sig")


def test_fingerprint_pubkey_mismatch(tmp_path):
    sig_path = tmp_path / "test.sig"
    data = {
        "modelsign_version": "1.0",
        "file": "m.bin", "sha256": "a" * 64,
        "signature": "sig", "algorithm": "ed25519",
        "signed_at": "2026-01-01T00:00:00Z",
        "public_key": "cHVia2V5",
        "key_fingerprint": "ed25519:ffffffff",
        "identity": {"name": "test"},
    }
    sig_path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="fingerprint.*mismatch"):
        read_sig(sig_path, validate_fingerprint=True)
