"""Click-based CLI for modelsign — sign, verify, inspect AI models."""

import base64
import json
import sys
import time
from pathlib import Path

import click

import modelsign
from modelsign.crypto.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    compute_fingerprint,
    public_key_to_bytes,
    keyring_add,
    keyring_list,
    keyring_remove,
)
from modelsign.crypto.sign import sign_bytes, build_file_message, build_dir_message
from modelsign.crypto.verify import verify_bytes
from modelsign.formats.single import hash_file
from modelsign.formats.directory import hash_directory
from modelsign.identity.card import ModelCard, validate_card
from modelsign.identity.canonical import canonical_json
from modelsign.sig import SigFile, write_sig, read_sig

DEFAULT_KEY_DIR = Path.home() / ".modelsign"


@click.group()
def main():
    """modelsign — Sign AI models with identity. Verify anywhere."""


@main.command()
def version():
    """Print modelsign version."""
    click.echo(modelsign.__version__)


@main.command()
@click.option("--out", "out_path", default=None, help="Path for private key PEM file.")
def keygen(out_path):
    """Generate an Ed25519 keypair."""
    if out_path is not None:
        priv_path = Path(out_path)
        key_dir = priv_path.parent
        # generate_keypair always creates private.pem + public.pem in the dir.
        # We need to handle a custom private key name — generate into a temp subdir
        # then move, OR: call generate_keypair on the parent dir and rename if needed.
        # Simplest: generate into parent dir under standard names, then rename to desired.
        tmp_priv = key_dir / "private.pem"
        tmp_pub = key_dir / "public.pem"

        # If already exists at out_path, just report fingerprint.
        if priv_path.exists():
            pub_path = _find_pubkey_for_private(priv_path)
            priv_key = load_private_key(priv_path)
            fp = compute_fingerprint(priv_key.public_key())
            click.echo(f"Key already exists: {priv_path}")
            click.echo(f"Fingerprint: {fp}")
            return

        key_dir.mkdir(parents=True, exist_ok=True)

        if priv_path.name != "private.pem":
            # Generate with standard names then rename
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            import os

            private_key = Ed25519PrivateKey.generate()
            priv_path.write_bytes(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            os.chmod(priv_path, 0o600)

            pub_path = priv_path.parent / (priv_path.stem + "_public.pem")
            # Use sibling public.pem convention
            pub_path = priv_path.with_name("public.pem")
            pub_path.write_bytes(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            fp = compute_fingerprint(private_key.public_key())
        else:
            actual_priv, actual_pub = generate_keypair(key_dir)
            priv_key = load_private_key(actual_priv)
            fp = compute_fingerprint(priv_key.public_key())
    else:
        priv_path, pub_path = generate_keypair(DEFAULT_KEY_DIR)
        priv_key = load_private_key(priv_path)
        fp = compute_fingerprint(priv_key.public_key())

    click.echo(f"Private key: {priv_path}")
    pub_path = _find_pubkey_for_private(priv_path)
    click.echo(f"Public key:  {pub_path}")
    click.echo(f"Fingerprint: {fp}")


def _find_pubkey_for_private(priv_path: Path) -> Path:
    """Locate the public key alongside a private key."""
    # Standard convention: public.pem lives next to private.pem
    pub = priv_path.parent / "public.pem"
    if pub.exists():
        return pub
    # Fallback: same stem with _public suffix
    pub2 = priv_path.with_name(priv_path.stem + "_public.pem")
    if pub2.exists():
        return pub2
    return pub  # Return expected path even if missing (for display)


@main.command()
@click.argument("model_path")
@click.option("--name", default=None, help="Model name (required if --identity not given).")
@click.option("--identity", "identity_file", default=None, help="Path to JSON identity card file.")
@click.option("--key", "key_path", default=None, help="Path to private key PEM file.")
@click.option("--out", "out_path", default=None, help="Output .sig file path (default: MODEL.sig).")
def sign(model_path, name, identity_file, key_path, out_path):
    """Sign a model file or directory."""
    model_path = Path(model_path)
    if not model_path.exists():
        click.echo(f"Error: model not found: {model_path}", err=True)
        sys.exit(1)

    # Resolve private key
    if key_path is not None:
        priv_key_path = Path(key_path)
    else:
        priv_key_path = DEFAULT_KEY_DIR / "private.pem"
        if not priv_key_path.exists():
            click.echo(
                f"Error: no key found at {priv_key_path}. Run 'modelsign keygen' first.",
                err=True,
            )
            sys.exit(1)

    try:
        private_key = load_private_key(priv_key_path)
    except Exception as e:
        click.echo(f"Error loading private key: {e}", err=True)
        sys.exit(1)

    pub_key = private_key.public_key()
    fingerprint = compute_fingerprint(pub_key)
    pub_key_b64 = base64.b64encode(public_key_to_bytes(pub_key)).decode("ascii")

    # Build identity card
    if identity_file is not None:
        try:
            card_data = json.loads(Path(identity_file).read_text())
            card = ModelCard.from_dict(card_data)
        except Exception as e:
            click.echo(f"Error reading identity file: {e}", err=True)
            sys.exit(1)
    elif name is not None:
        card = ModelCard(name=name)
    else:
        click.echo("Error: provide --name or --identity.", err=True)
        sys.exit(1)

    try:
        validate_card(card)
    except ValueError as e:
        click.echo(f"Error: invalid identity card: {e}", err=True)
        sys.exit(1)

    identity_dict = card.to_dict()
    identity_bytes = canonical_json(identity_dict)

    # Hash model and build message
    manifest = None
    if model_path.is_dir():
        manifest, model_hash = hash_directory(model_path)
        message = build_dir_message(model_hash, identity_bytes)
        file_label = str(model_path)
    else:
        model_hash = hash_file(model_path)
        message = build_file_message(model_hash, identity_bytes)
        file_label = model_path.name

    # Sign
    signature_bytes = sign_bytes(message, private_key)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    sig = SigFile(
        modelsign_version="1.0",
        file=file_label,
        sha256=f"sha256:{model_hash}",
        signature=signature_b64,
        algorithm="ed25519",
        signed_at=signed_at,
        public_key=pub_key_b64,
        key_fingerprint=fingerprint,
        identity=identity_dict,
        manifest=manifest,
    )

    sig_path = Path(out_path) if out_path else Path(str(model_path) + ".sig")
    write_sig(sig, sig_path)

    click.echo(f"Signed:      {model_path}")
    click.echo(f"Sig file:    {sig_path}")
    click.echo(f"Fingerprint: {fingerprint}")
    click.echo(f"SHA-256:     sha256:{model_hash[:16]}...")


@main.command()
@click.argument("model_path")
@click.option("--sig", "sig_path", default=None, help="Path to .sig file (default: MODEL.sig).")
@click.option("--pubkey", "pubkey_path", default=None, help="Path to trusted public key PEM.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output JSON.")
@click.option("--quiet", is_flag=True, default=False, help="Suppress output; use exit code only.")
def verify(model_path, sig_path, pubkey_path, output_json, quiet):
    """Verify a signed model file or directory."""
    model_path = Path(model_path)

    # Locate sig file
    if sig_path is not None:
        sig_file_path = Path(sig_path)
    else:
        sig_file_path = Path(str(model_path) + ".sig")

    if not sig_file_path.exists():
        if not quiet:
            click.echo(f"Error: sig file not found: {sig_file_path}", err=True)
        sys.exit(2)

    if not model_path.exists():
        if not quiet:
            click.echo(f"Error: model not found: {model_path}", err=True)
        sys.exit(2)

    # Read sig (C2 fix: validate fingerprint matches embedded public key)
    try:
        sig = read_sig(sig_file_path, validate_fingerprint=True)
    except ValueError as e:
        if not quiet:
            click.echo(f"FAILED {model_path.name}\n  Sig file corrupted: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        if not quiet:
            click.echo(f"Error reading sig file: {e}", err=True)
        sys.exit(2)

    # Reconstruct public key for verification
    # C3 fix: warn loudly when using embedded key (no independent trust verification)
    using_trusted_key = False
    try:
        if pubkey_path is not None:
            pub_key = load_public_key(Path(pubkey_path))
            using_trusted_key = True
        else:
            # Check keyring for matching key
            keyring_dir = DEFAULT_KEY_DIR / "keyring"
            trusted_keys = keyring_list(keyring_dir)
            matched_trust = None
            for entry in trusted_keys:
                if entry["fingerprint"] == sig.key_fingerprint:
                    pub_key = load_public_key(Path(entry["path"]))
                    using_trusted_key = True
                    matched_trust = entry["alias"]
                    break

            if not using_trusted_key:
                # Fall back to embedded key — but WARN the user
                raw_pub = base64.b64decode(sig.public_key)
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
    except Exception as e:
        if not quiet:
            click.echo(f"Error loading public key: {e}", err=True)
        sys.exit(2)

    # Hash model
    try:
        if model_path.is_dir():
            _, model_hash = hash_directory(model_path)
        else:
            model_hash = hash_file(model_path)
    except Exception as e:
        if not quiet:
            click.echo(f"Error hashing model: {e}", err=True)
        sys.exit(2)

    # C1 fix: check file hash against sig BEFORE verifying signature
    # sig.sha256 is stored as "sha256:<hex>", model_hash is raw hex
    expected_hash = sig.sha256
    if expected_hash.startswith("sha256:"):
        expected_hash = expected_hash[7:]
    if model_hash != expected_hash:
        if output_json:
            click.echo(json.dumps({"verified": False, "error": "hash mismatch",
                                   "detail": "file has been modified since signing"}))
        elif not quiet:
            click.echo(f"FAILED {model_path.name}\n  Hash mismatch — file has been modified since signing.")
        sys.exit(1)

    # Rebuild message and verify signature
    identity_bytes = canonical_json(sig.identity)
    if model_path.is_dir():
        message = build_dir_message(model_hash, identity_bytes)
    else:
        message = build_file_message(model_hash, identity_bytes)

    try:
        signature_bytes = base64.b64decode(sig.signature)
    except Exception as e:
        if not quiet:
            click.echo(f"Error decoding signature: {e}", err=True)
        sys.exit(2)

    ok = verify_bytes(message, signature_bytes, pub_key)

    if not ok:
        if output_json:
            click.echo(json.dumps({"verified": False, "error": "invalid signature",
                                   "detail": "signature or identity card has been tampered with"}))
        elif not quiet:
            click.echo(f"FAILED {model_path.name}\n  Invalid signature — sig file may have been tampered with.")
        sys.exit(1)

    # Determine trust level for display
    fp = compute_fingerprint(pub_key)
    if pubkey_path:
        trust_label = "TRUSTED (--pubkey)"
    elif using_trusted_key:
        trust_label = f"TRUSTED (keyring: {matched_trust})"
    else:
        trust_label = "UNVERIFIED — using embedded key, not independently trusted"

    if output_json:
        result = {
            "verified": True,
            "model": str(model_path),
            "sha256": f"sha256:{model_hash}",
            "fingerprint": fp,
            "trust": trust_label,
            "signed_at": sig.signed_at,
            "identity": sig.identity,
        }
        click.echo(json.dumps(result))
        return

    if quiet:
        return

    click.echo(f"VERIFIED {model_path.name}")
    click.echo(f"  Name:         {sig.identity.get('name', '(unnamed)')}")
    if sig.identity.get("creator"):
        click.echo(f"  Creator:      {sig.identity['creator']}")
    if sig.identity.get("architecture"):
        click.echo(f"  Architecture: {sig.identity['architecture']}")
    if sig.identity.get("base_model"):
        click.echo(f"  Base model:   {sig.identity['base_model']}")
    if sig.identity.get("license"):
        click.echo(f"  License:      {sig.identity['license']}")
    click.echo(f"  Signed:       {sig.signed_at} (unverified — no RFC 3161 timestamp)")
    click.echo(f"  Key:          {fp} ({trust_label})")
    if not using_trusted_key:
        click.echo(f"  WARNING: key not in keyring. Run 'modelsign keyring add <pubkey> <alias>' to trust it.")


@main.command()
@click.argument("sig_file")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output raw JSON.")
def inspect(sig_file, output_json):
    """Inspect a .sig file and display identity card."""
    sig_path = Path(sig_file)

    try:
        sig = read_sig(sig_path)
    except FileNotFoundError:
        click.echo(f"Error: sig file not found: {sig_path}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error reading sig file: {e}", err=True)
        sys.exit(1)

    if output_json:
        from dataclasses import asdict
        click.echo(json.dumps(asdict(sig), indent=2))
        return

    # Human-readable output
    click.echo(f"File:        {sig.file}")
    click.echo(f"SHA-256:     {sig.sha256}")
    click.echo(f"Algorithm:   {sig.algorithm}")
    click.echo(f"Fingerprint: {sig.key_fingerprint}")
    click.echo(f"Signed at:   {sig.signed_at}")
    click.echo("Identity:")
    for key, val in sig.identity.items():
        if isinstance(val, dict):
            click.echo(f"  {key}:")
            for k2, v2 in val.items():
                click.echo(f"    {k2}: {v2}")
        else:
            click.echo(f"  {key}: {val}")


@main.group()
def keyring():
    """Manage trusted public keys."""


@keyring.command("add")
@click.argument("pubkey_path")
@click.argument("alias")
@click.option("--keyring-dir", default=None, help="Keyring directory (default: ~/.modelsign/keyring).")
def keyring_add_cmd(pubkey_path, alias, keyring_dir):
    """Add a public key to the trusted keyring."""
    kr_dir = Path(keyring_dir) if keyring_dir else DEFAULT_KEY_DIR / "keyring"
    try:
        keyring_add(kr_dir, Path(pubkey_path), alias)
        click.echo(f"Added key '{alias}' to keyring at {kr_dir}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@keyring.command("list")
@click.option("--keyring-dir", default=None, help="Keyring directory (default: ~/.modelsign/keyring).")
def keyring_list_cmd(keyring_dir):
    """List all trusted public keys."""
    kr_dir = Path(keyring_dir) if keyring_dir else DEFAULT_KEY_DIR / "keyring"
    keys = keyring_list(kr_dir)
    if not keys:
        click.echo("No keys in keyring.")
        return
    for entry in keys:
        click.echo(f"{entry['alias']:<20} {entry['fingerprint']}  {entry['path']}")


@keyring.command("remove")
@click.argument("alias")
@click.option("--keyring-dir", default=None, help="Keyring directory (default: ~/.modelsign/keyring).")
def keyring_remove_cmd(alias, keyring_dir):
    """Remove a key from the trusted keyring."""
    kr_dir = Path(keyring_dir) if keyring_dir else DEFAULT_KEY_DIR / "keyring"
    try:
        keyring_remove(kr_dir, alias)
        click.echo(f"Removed key '{alias}' from keyring.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
