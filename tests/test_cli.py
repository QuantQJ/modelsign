"""CLI integration tests using Click's CliRunner."""

import json
from pathlib import Path
from click.testing import CliRunner
from modelsign.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    import modelsign
    assert modelsign.__version__ in result.output


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


def test_verify_without_pubkey_warns_untrusted(tmp_path):
    """C3 regression: verify without --pubkey must warn about untrusted embedded key."""
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"fake-model-untrusted-test")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "untrusted-test",
        "--key", str(key_dir / "private.pem"),
    ])

    # Verify WITHOUT --pubkey — a key nobody vouched for is now refused.
    result = runner.invoke(main, ["verify", str(model_path)])
    assert result.exit_code == 1
    assert "untrusted key" in result.output

    # Integrity without identity is available, and says so.
    allowed = runner.invoke(main, ["verify", str(model_path), "--allow-embedded-key"])
    assert allowed.exit_code == 0
    assert "VERIFIED" in allowed.output
    assert (
        "UNVERIFIED" in allowed.output
        or "WARNING" in allowed.output
        or "not independently trusted" in allowed.output
    )


def test_verify_tampered_file_shows_hash_mismatch(tmp_path):
    """C1 regression: tampered file must show 'hash mismatch', not generic sig failure."""
    runner = CliRunner()

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(key_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"original-weights")

    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "hash-test",
        "--key", str(key_dir / "private.pem"),
    ])

    model_path.write_bytes(b"tampered-weights")

    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(key_dir / "public.pem"),
    ])
    assert result.exit_code != 0
    assert "Hash mismatch" in result.output or "hash mismatch" in result.output


def test_verify_forged_sig_fails(tmp_path):
    """C3 regression: attacker-signed file with attacker key must still fail with --pubkey."""
    runner = CliRunner()

    # Legitimate key
    legit_dir = tmp_path / "legit"
    legit_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(legit_dir / "private.pem")])

    # Attacker key
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir()
    runner.invoke(main, ["keygen", "--out", str(attacker_dir / "private.pem")])

    model_path = tmp_path / "model.safetensors"
    model_path.write_bytes(b"attacker-controlled-weights")

    # Attacker signs with their key
    runner.invoke(main, [
        "sign", str(model_path),
        "--name", "legit-looking-model",
        "--key", str(attacker_dir / "private.pem"),
    ])

    # Verify with legitimate pubkey — must FAIL
    result = runner.invoke(main, [
        "verify", str(model_path),
        "--pubkey", str(legit_dir / "public.pem"),
    ])
    assert result.exit_code != 0
    assert "FAILED" in result.output


def test_oms_keygen_export_and_verify(tmp_path):
    """The OMS subcommands work end to end on a model directory."""
    from click.testing import CliRunner

    from modelsign.cli import main

    runner = CliRunner()
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights")
    (model / "config.json").write_bytes(b'{"model_type":"llama"}')

    keys = runner.invoke(main, ["oms", "keygen", "--dir", str(tmp_path / "keys")])
    assert keys.exit_code == 0
    priv = tmp_path / "keys" / "oms_private.pem"
    pub = tmp_path / "keys" / "oms_public.pem"

    exported = runner.invoke(
        main,
        ["oms", "export", str(model), "--key", str(priv), "--out", str(model / "model.sig")],
    )
    assert exported.exit_code == 0
    assert "OpenSSF Model Signing" in exported.output

    verified = runner.invoke(main, ["oms", "verify", str(model), "--pubkey", str(pub)])
    assert verified.exit_code == 0
    assert "VERIFIED" in verified.output


def test_oms_verify_fails_on_tampered_model(tmp_path):
    from click.testing import CliRunner

    from modelsign.cli import main

    runner = CliRunner()
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights")

    runner.invoke(main, ["oms", "keygen", "--dir", str(tmp_path / "keys")])
    priv = tmp_path / "keys" / "oms_private.pem"
    pub = tmp_path / "keys" / "oms_public.pem"
    runner.invoke(
        main,
        ["oms", "export", str(model), "--key", str(priv), "--out", str(model / "model.sig")],
    )
    (model / "model.safetensors").write_bytes(b"swapped")

    result = runner.invoke(main, ["oms", "verify", str(model), "--pubkey", str(pub)])
    assert result.exit_code == 1
    assert "FAILED" in result.output


def test_oms_export_rejects_ed25519_key(tmp_path, tmp_keypair):
    from click.testing import CliRunner

    from modelsign.cli import main

    model = tmp_path / "m.safetensors"
    model.write_bytes(b"weights")
    result = CliRunner().invoke(
        main, ["oms", "export", str(model), "--key", str(tmp_keypair["private"])]
    )
    assert result.exit_code == 1
    assert "ECDSA" in result.output
