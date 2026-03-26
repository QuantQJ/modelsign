"""CLI integration tests using Click's CliRunner."""

import json
from pathlib import Path
from click.testing import CliRunner
from modelsign.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_keygen(tmp_path):
    runner = CliRunner()
    out_path = str(tmp_path / "test.pem")
    result = runner.invoke(main, ["keygen", "--out", out_path])
    assert result.exit_code == 0
    assert Path(out_path).exists()
    assert "ed25519:" in result.output


def test_sign_verify_roundtrip(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model-weights-12345")

    result = runner.invoke(main, [
        "sign", str(model_path),
        "--name", "test-model",
        "--key", str(key_dir / "private.pem"),
    ])
    assert result.exit_code == 0
    assert Path(str(model_path) + ".sig").exists()

    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(key_dir / "public.pem"),
    ])
    assert result.exit_code == 0
    assert "VERIFIED" in result.output


def test_sign_with_identity_file(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model-weights")

    identity_file = tmp_path / "card.json"
    identity_file.write_text(json.dumps({
        "name": "My-Model",
        "creator": "QJ",
        "architecture": "LlamaForCausalLM",
    }))

    result = runner.invoke(main, [
        "sign", str(model_path),
        "--identity", str(identity_file),
        "--key", str(key_dir / "private.pem"),
    ])
    assert result.exit_code == 0


def test_verify_tampered_file(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"original-weights")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "test",
        "--key", str(key_dir / "private.pem"),
    ])

    model_path.write_bytes(b"tampered-weights")

    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(key_dir / "public.pem"),
    ])
    assert result.exit_code != 0
    assert "FAILED" in result.output


def test_inspect(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "inspect-test",
        "--key", str(key_dir / "private.pem"),
    ])

    result = runner.invoke(main, ["inspect", str(model_path) + ".sig"])
    assert result.exit_code == 0
    assert "inspect-test" in result.output


def test_inspect_json(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "json-test",
        "--key", str(key_dir / "private.pem"),
    ])

    result = runner.invoke(main, ["inspect", str(model_path) + ".sig", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["identity"]["name"] == "json-test"


def test_verify_quiet(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "quiet-test",
        "--key", str(key_dir / "private.pem"),
    ])

    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(key_dir / "public.pem"),
        "--quiet",
    ])
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_verify_json_output(tmp_path):
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "json-verify",
        "--key", str(key_dir / "private.pem"),
    ])

    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(key_dir / "public.pem"),
        "--json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verified"] is True
    assert data["identity"]["name"] == "json-verify"
