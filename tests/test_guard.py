"""Tests for load-time verification.

A stand-in huggingface_hub module keeps these tests offline: it serves files
from a local directory the way the real download functions serve them from
the Hub cache.
"""

import shutil
import sys
import types

import pytest

from modelsign import guard
from modelsign.api import sign_model


@pytest.fixture
def fake_hub(tmp_path, monkeypatch):
    """A module named huggingface_hub whose downloads come from a local repo dir."""
    repo = tmp_path / "remote-repo"
    repo.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()

    module = types.ModuleType("huggingface_hub")

    def hf_hub_download(repo_id, filename, **kwargs):
        src = repo / filename
        if not src.exists():
            raise FileNotFoundError(f"404 {repo_id}/{filename}")
        dst = cache / filename
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return str(dst)

    def snapshot_download(repo_id, **kwargs):
        dst = cache / "snapshot"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(repo, dst)
        repo_sig = repo.parent / (repo.name + ".sig")
        if repo_sig.exists():
            shutil.copy2(repo_sig, str(dst) + ".sig")
        return str(dst)

    module.hf_hub_download = hf_hub_download
    module.snapshot_download = snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", module)

    yield types.SimpleNamespace(module=module, repo=repo, cache=cache)
    guard.uninstall()


def _publish(fake, keypair, name="model.safetensors", sign=True):
    """Put a model in the fake repo, signed by default."""
    path = fake.repo / name
    path.write_bytes(b"weights-" + name.encode())
    if sign:
        sign_model(path, name="Published-Model", key=keypair["private"])
    return path


# -- require_verified ---------------------------------------------------


def test_require_verified_passes_signed_model(tmp_keypair, tmp_model_file):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    result = guard.require_verified(tmp_model_file, pubkey=tmp_keypair["public"])
    assert result.verified


def test_require_verified_blocks_modified_model(tmp_keypair, tmp_model_file):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    tmp_model_file.write_bytes(b"swapped-weights")
    with pytest.raises(guard.LoadBlocked) as excinfo:
        guard.require_verified(tmp_model_file, pubkey=tmp_keypair["public"])
    assert "hash mismatch" in str(excinfo.value)
    assert excinfo.value.result.error == "hash mismatch"


def test_require_verified_blocks_unknown_signer(tmp_keypair, tmp_model_file, tmp_path):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    with pytest.raises(guard.LoadBlocked):
        guard.require_verified(tmp_model_file, keyring_dir=tmp_path / "empty")


def test_require_verified_allows_embedded_when_asked(
    tmp_keypair, tmp_model_file, tmp_path
):
    sign_model(tmp_model_file, name="Test-Model", key=tmp_keypair["private"])
    result = guard.require_verified(
        tmp_model_file, keyring_dir=tmp_path / "empty", allow_embedded=True
    )
    assert result.verified
    assert result.trusted is False


def test_require_verified_blocks_missing_signature(tmp_model_file):
    with pytest.raises(guard.LoadBlocked):
        guard.require_verified(tmp_model_file)


# -- hub patching -------------------------------------------------------


def test_install_is_idempotent_and_reversible(fake_hub):
    original = fake_hub.module.hf_hub_download
    guard.install(allow_unsigned=True)
    guard.install(allow_unsigned=True)
    assert guard.is_installed()
    assert fake_hub.module.hf_hub_download is not original
    guard.uninstall()
    assert not guard.is_installed()
    assert fake_hub.module.hf_hub_download is original


def test_guarded_download_returns_signed_file(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair)
    guard.install(pubkey=tmp_keypair["public"])
    path = fake_hub.module.hf_hub_download("acme/model", "model.safetensors")
    assert path.endswith("model.safetensors")


def test_guarded_download_fetches_sig_from_repo(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair)
    guard.install(pubkey=tmp_keypair["public"])
    fake_hub.module.hf_hub_download("acme/model", "model.safetensors")
    # The signature was pulled alongside the weights, not assumed present.
    assert (fake_hub.cache / "model.safetensors.sig").exists()


def test_guarded_download_blocks_unsigned_weights(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="naked.safetensors", sign=False)
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.hf_hub_download("acme/model", "naked.safetensors")
    assert "no signature" in str(excinfo.value)


def test_allow_unsigned_lets_unsigned_weights_through(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="naked.safetensors", sign=False)
    guard.install(pubkey=tmp_keypair["public"], allow_unsigned=True)
    path = fake_hub.module.hf_hub_download("acme/model", "naked.safetensors")
    assert path.endswith("naked.safetensors")


def test_guarded_download_blocks_tampered_weights(fake_hub, tmp_keypair):
    path = _publish(fake_hub, tmp_keypair)
    path.write_bytes(b"swapped-after-signing")
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.hf_hub_download("acme/model", "model.safetensors")


def test_guarded_download_blocks_signature_from_unknown_key(
    fake_hub, tmp_keypair, tmp_path
):
    _publish(fake_hub, tmp_keypair)
    guard.install(keyring_dir=tmp_path / "empty")
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.hf_hub_download("acme/model", "model.safetensors")


def test_env_var_supplies_the_trusted_key(fake_hub, tmp_keypair, monkeypatch):
    _publish(fake_hub, tmp_keypair)
    monkeypatch.setenv("MODELSIGN_PUBKEY", str(tmp_keypair["public"]))
    guard.install()
    assert fake_hub.module.hf_hub_download("acme/model", "model.safetensors")


def test_guarded_snapshot_verifies_each_signed_file(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="a.safetensors")
    _publish(fake_hub, tmp_keypair, name="b.safetensors")
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    local = fake_hub.module.snapshot_download("acme/model")
    assert local.endswith("snapshot")


def test_guarded_snapshot_blocks_one_tampered_shard(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="a.safetensors")
    bad = _publish(fake_hub, tmp_keypair, name="b.safetensors")
    bad.write_bytes(b"swapped-after-signing")
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.snapshot_download("acme/model")


def test_guarded_snapshot_blocks_wholly_unsigned_repo(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="a.safetensors", sign=False)
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.snapshot_download("acme/model")


# -- the snapshot path must not verify only the files that happen to be signed


def test_guarded_snapshot_blocks_unsigned_file_beside_signed_one(fake_hub, tmp_keypair):
    """A signed model next to an unsigned file must not let the pair through."""
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    _publish(fake_hub, tmp_keypair, name="pytorch_model.bin", sign=False)
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "pytorch_model.bin" in str(excinfo.value)


def test_guarded_snapshot_names_every_unsigned_file(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    _publish(fake_hub, tmp_keypair, name="sneaky.pkl", sign=False)
    _publish(fake_hub, tmp_keypair, name="also_sneaky.bin", sign=False)
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    message = str(excinfo.value)
    assert "sneaky.pkl" in message and "also_sneaky.bin" in message


def test_guarded_snapshot_blocks_unsigned_file_in_subdirectory(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    nested = fake_hub.repo / "onnx"
    nested.mkdir()
    (nested / "model.onnx").write_bytes(b"unsigned-nested-weights")
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "onnx/model.onnx" in str(excinfo.value)


def test_whole_directory_signature_covers_unsigned_files(fake_hub, tmp_keypair):
    """A directory signature's manifest covers every file, so no per-file sigs needed."""
    (fake_hub.repo / "config.json").write_bytes(b'{"model_type":"llama"}')
    (fake_hub.repo / "model.safetensors").write_bytes(b"weights")
    sign_model(
        fake_hub.repo,
        name="Whole-Repo",
        key=tmp_keypair["private"],
        sig_path=str(fake_hub.repo) + ".sig",
    )
    guard.install(pubkey=tmp_keypair["public"])
    assert fake_hub.module.snapshot_download("acme/model")


def test_whole_directory_signature_catches_an_added_file(fake_hub, tmp_keypair):
    (fake_hub.repo / "model.safetensors").write_bytes(b"weights")
    sign_model(
        fake_hub.repo,
        name="Whole-Repo",
        key=tmp_keypair["private"],
        sig_path=str(fake_hub.repo) + ".sig",
    )
    (fake_hub.repo / "smuggled.pkl").write_bytes(b"added-after-signing")
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.snapshot_download("acme/model")


def test_allow_unsigned_still_bypasses_the_snapshot_check(fake_hub, tmp_keypair):
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    _publish(fake_hub, tmp_keypair, name="extra.bin", sign=False)
    guard.install(
        pubkey=tmp_keypair["public"], allow_unsigned=True, allow_per_file=True
    )
    assert fake_hub.module.snapshot_download("acme/model")


# -- OMS bundles are honoured at the same chokepoint


@pytest.fixture
def ec_pub(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    priv, pub = tmp_path / "oms_priv.pem", tmp_path / "oms_pub.pem"
    priv.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return {"private": priv, "public": pub}


def _publish_oms(fake_hub, ec_pub):
    """Sign the fake repo into an OMS bundle at the conventional path."""
    from modelsign.oms import DEFAULT_BUNDLE_NAME, export_bundle

    (fake_hub.repo / "model.safetensors").write_bytes(b"oms-weights")
    (fake_hub.repo / "config.json").write_bytes(b'{"model_type":"llama"}')
    export_bundle(
        fake_hub.repo,
        key=ec_pub["private"],
        name="acme/model",
        out=fake_hub.repo / DEFAULT_BUNDLE_NAME,
    )


def test_guard_accepts_an_oms_signed_snapshot(fake_hub, ec_pub):
    _publish_oms(fake_hub, ec_pub)
    guard.install(oms_pubkey=ec_pub["public"])
    assert fake_hub.module.snapshot_download("acme/model")


def test_guard_blocks_a_tampered_oms_snapshot(fake_hub, ec_pub):
    _publish_oms(fake_hub, ec_pub)
    (fake_hub.repo / "model.safetensors").write_bytes(b"swapped-after-signing")
    guard.install(oms_pubkey=ec_pub["public"])
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "hash mismatch" in str(excinfo.value)


def test_guard_blocks_a_file_smuggled_into_an_oms_snapshot(fake_hub, ec_pub):
    _publish_oms(fake_hub, ec_pub)
    (fake_hub.repo / "smuggled.pkl").write_bytes(b"not in the manifest")
    guard.install(oms_pubkey=ec_pub["public"])
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "smuggled.pkl" in str(excinfo.value)


def test_oms_bundle_is_ignored_without_a_configured_key(fake_hub, ec_pub, tmp_keypair):
    """An OMS bundle we have no key for must not count as a signature."""
    _publish_oms(fake_hub, ec_pub)
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.snapshot_download("acme/model")


def test_oms_env_var_supplies_the_key(fake_hub, ec_pub, monkeypatch):
    _publish_oms(fake_hub, ec_pub)
    monkeypatch.setenv("MODELSIGN_OMS_PUBKEY", str(ec_pub["public"]))
    guard.install()
    assert fake_hub.module.snapshot_download("acme/model")


# -- a reference bound before install() must still be guarded


def test_install_rebinds_an_already_imported_reference(fake_hub, tmp_keypair):
    """`from huggingface_hub import hf_hub_download` binds the function object.

    transformers does exactly that, so patching only the package attribute
    would leave the import-time binding pointing at the unguarded original.
    """
    import sys
    import types

    consumer = types.ModuleType("pretend_transformers")
    consumer.hf_hub_download = fake_hub.module.hf_hub_download  # bound early
    sys.modules["pretend_transformers"] = consumer
    try:
        _publish(fake_hub, tmp_keypair, name="naked.safetensors", sign=False)
        guard.install(pubkey=tmp_keypair["public"])

        assert getattr(consumer.hf_hub_download, "_modelsign_guarded", False) is True
        with pytest.raises(guard.LoadBlocked):
            consumer.hf_hub_download("acme/model", "naked.safetensors")

        guard.uninstall()
        # and the early binding is restored, not left pointing at the wrapper
        assert not getattr(consumer.hf_hub_download, "_modelsign_guarded", False)
    finally:
        sys.modules.pop("pretend_transformers", None)


def test_uninstall_restores_every_patched_reference(fake_hub, tmp_keypair):
    import sys
    import types

    consumer = types.ModuleType("pretend_consumer")
    original = fake_hub.module.hf_hub_download
    consumer.hf_hub_download = original
    sys.modules["pretend_consumer"] = consumer
    try:
        guard.install(pubkey=tmp_keypair["public"])
        guard.uninstall()
        assert consumer.hf_hub_download is original
        assert fake_hub.module.hf_hub_download is original
    finally:
        sys.modules.pop("pretend_consumer", None)


def test_guard_rejects_an_unbound_name_by_default(
    fake_hub, tmp_keypair, tmp_path, write_v1_sig
):
    """At the load chokepoint a 1.x single-file signature is not good enough."""
    model = tmp_path / "legacy.safetensors"
    model.write_bytes(b"weights")
    write_v1_sig(model, tmp_keypair)

    with pytest.raises(guard.LoadBlocked) as excinfo:
        guard.require_verified(model, pubkey=tmp_keypair["public"])
    assert "unauthenticated name" in str(excinfo.value)

    # and the escape hatch is explicit
    assert guard.require_verified(
        model, pubkey=tmp_keypair["public"], allow_unbound_names=True
    ).verified


def test_per_file_mode_refuses_duplicate_basenames(fake_hub, tmp_keypair):
    """Basename-only binding makes same-named files in different dirs swappable."""
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    nested = fake_hub.repo / "onnx"
    nested.mkdir()
    target = nested / "model.safetensors"
    target.write_bytes(b"different-weights")
    from modelsign.api import sign_model

    sign_model(target, name="Published-Model", key=tmp_keypair["private"])

    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    message = str(excinfo.value)
    assert "basename only" in message
    assert "onnx/model.safetensors" in message


def test_directory_signature_has_no_basename_ambiguity(fake_hub, tmp_keypair):
    """The same layout verifies fine under a directory signature."""
    from modelsign.api import sign_model

    (fake_hub.repo / "model.safetensors").write_bytes(b"weights")
    nested = fake_hub.repo / "onnx"
    nested.mkdir()
    (nested / "model.safetensors").write_bytes(b"different-weights")
    sign_model(
        fake_hub.repo,
        name="Whole-Repo",
        key=tmp_keypair["private"],
        sig_path=str(fake_hub.repo) + ".sig",
    )
    guard.install(pubkey=tmp_keypair["public"])
    assert fake_hub.module.snapshot_download("acme/model")


def test_per_file_signatures_are_refused_by_default(fake_hub, tmp_keypair):
    """A snapshot needs a signature over the whole directory, not per file.

    Per-file signatures bind a basename, never a path, so they cannot say
    where in a repository a file belongs.
    """
    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    message = str(excinfo.value)
    assert "no directory signature" in message
    assert "allow_per_file=True" in message


# -- review findings: the guard must not hand back unverified weights


def test_allow_unsigned_still_verifies_the_files_that_are_signed(
    fake_hub, tmp_keypair
):
    """allow_unsigned is about files with no signature, not a blanket pass.

    An earlier version returned as soon as it saw one unsigned file, skipping
    the digest check on the signed weights beside it.
    """
    signed = _publish(fake_hub, tmp_keypair, name="model.safetensors")
    _publish(fake_hub, tmp_keypair, name="README.md", sign=False)
    signed.write_bytes(b"BACKDOORED-AFTER-SIGNING")

    guard.install(
        pubkey=tmp_keypair["public"], allow_unsigned=True, allow_per_file=True
    )
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "hash mismatch" in str(excinfo.value)


def test_basename_clash_is_refused_even_with_allow_unsigned(fake_hub, tmp_keypair):
    """Path ambiguity is not a question about missing signatures."""
    from modelsign.api import sign_model

    _publish(fake_hub, tmp_keypair, name="model.safetensors")
    nested = fake_hub.repo / "onnx"
    nested.mkdir()
    target = nested / "model.safetensors"
    target.write_bytes(b"different-weights")
    sign_model(target, name="Published-Model", key=tmp_keypair["private"])

    guard.install(
        pubkey=tmp_keypair["public"], allow_unsigned=True, allow_per_file=True
    )
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_hub.module.snapshot_download("acme/model")
    assert "basename only" in str(excinfo.value)


def test_a_directory_signature_inside_the_repo_is_honoured(fake_hub, tmp_keypair):
    """A Hub download never writes outside the snapshot, so <dir>.sig is unreachable."""
    from modelsign.api import sign_model

    (fake_hub.repo / "model.safetensors").write_bytes(b"weights")
    (fake_hub.repo / "config.json").write_bytes(b'{"model_type":"llama"}')
    sign_model(
        fake_hub.repo,
        name="Published-Repo",
        key=tmp_keypair["private"],
        sig_path=fake_hub.repo / guard.DIR_SIG_NAME,
    )
    guard.install(pubkey=tmp_keypair["public"])
    assert fake_hub.module.snapshot_download("acme/model")


def test_in_repo_directory_signature_catches_a_smuggled_file(fake_hub, tmp_keypair):
    from modelsign.api import sign_model

    (fake_hub.repo / "model.safetensors").write_bytes(b"weights")
    sign_model(
        fake_hub.repo,
        name="Published-Repo",
        key=tmp_keypair["private"],
        sig_path=fake_hub.repo / guard.DIR_SIG_NAME,
    )
    (fake_hub.repo / "smuggled.pkl").write_bytes(b"added after signing")
    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked):
        fake_hub.module.snapshot_download("acme/model")


def test_a_malformed_sig_raises_load_blocked_not_a_raw_exception(
    fake_hub, tmp_keypair, tmp_path
):
    """Whatever an attacker puts in a .sig, the loader sees LoadBlocked."""
    import json

    from modelsign.api import default_sig_path, sign_model

    model = tmp_path / "model.safetensors"
    model.write_bytes(b"weights")
    sign_model(model, name="Test", key=tmp_keypair["private"])
    sig_path = default_sig_path(model)

    for mutate in (
        lambda d: d.update({"modelsign_version": "9.0"}),
        lambda d: d.pop("identity"),
        lambda d: d.update({"public_key": "###not-base64###"}),
        lambda d: d.update({"signature": None}),
    ):
        data = json.loads(sig_path.read_text())
        mutate(data)
        sig_path.write_text(json.dumps(data))
        with pytest.raises(guard.LoadBlocked):
            guard.require_verified(model, pubkey=tmp_keypair["public"])


def test_installing_a_second_different_policy_is_refused(fake_hub, tmp_keypair):
    """Silently keeping the first policy would mislead the stricter caller."""
    guard.install(pubkey=tmp_keypair["public"], allow_unsigned=True)
    with pytest.raises(RuntimeError) as excinfo:
        guard.install(pubkey=tmp_keypair["public"])
    assert "different policy" in str(excinfo.value)


def test_installing_the_same_policy_twice_is_fine(fake_hub, tmp_keypair):
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    guard.install(pubkey=tmp_keypair["public"], allow_per_file=True)
    assert guard.is_installed()


# -- local paths never reach the Hub hooks, so from_pretrained is guarded too


@pytest.fixture
def fake_transformers(monkeypatch):
    """A stand-in transformers whose PreTrainedModel records its calls."""
    import sys
    import types

    module = types.ModuleType("transformers")
    calls = []

    class PreTrainedModel:
        @classmethod
        def from_pretrained(cls, pretrained_model_name_or_path=None, *args, **kwargs):
            calls.append(pretrained_model_name_or_path)
            return f"loaded:{pretrained_model_name_or_path}"

    module.PreTrainedModel = PreTrainedModel
    monkeypatch.setitem(sys.modules, "transformers", module)
    yield types.SimpleNamespace(module=module, model=PreTrainedModel, calls=calls)
    guard.uninstall()


def test_unsigned_local_directory_is_refused(fake_transformers, tmp_keypair, tmp_path):
    model = tmp_path / "local-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights")

    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked):
        fake_transformers.model.from_pretrained(str(model))
    assert fake_transformers.calls == []


def test_signed_local_directory_loads(fake_transformers, tmp_keypair, tmp_path):
    from modelsign.api import sign_model

    model = tmp_path / "local-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights")
    sign_model(
        model,
        name="Local",
        key=tmp_keypair["private"],
        sig_path=model / guard.DIR_SIG_NAME,
    )

    guard.install(pubkey=tmp_keypair["public"])
    assert fake_transformers.model.from_pretrained(str(model)) == f"loaded:{model}"


def test_tampered_local_file_is_refused(fake_transformers, tmp_keypair, tmp_path):
    from modelsign.api import sign_model

    model = tmp_path / "model.safetensors"
    model.write_bytes(b"weights")
    sign_model(model, name="Local", key=tmp_keypair["private"])
    model.write_bytes(b"swapped")

    guard.install(pubkey=tmp_keypair["public"])
    with pytest.raises(guard.LoadBlocked) as excinfo:
        fake_transformers.model.from_pretrained(str(model))
    assert "hash mismatch" in str(excinfo.value)


def test_a_repo_id_is_left_to_the_hub_hooks(fake_transformers, tmp_keypair):
    """Not a local path, so from_pretrained passes it through to be downloaded."""
    guard.install(pubkey=tmp_keypair["public"])
    assert fake_transformers.model.from_pretrained("acme/llama-8b") == "loaded:acme/llama-8b"


def test_uninstall_restores_from_pretrained(fake_transformers, tmp_keypair):
    original = fake_transformers.model.__dict__["from_pretrained"]
    guard.install(pubkey=tmp_keypair["public"])
    assert fake_transformers.model.__dict__["from_pretrained"] is not original
    guard.uninstall()
    assert fake_transformers.model.__dict__["from_pretrained"] is original


def test_cover_local_can_be_turned_off(fake_transformers, tmp_keypair, tmp_path):
    model = tmp_path / "local-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights")

    guard.install(pubkey=tmp_keypair["public"], cover_local=False)
    assert fake_transformers.model.from_pretrained(str(model)) == f"loaded:{model}"
