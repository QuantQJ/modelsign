"""Click-based CLI for modelsign — sign, verify, inspect AI models."""

import json
import os
import sys
from pathlib import Path

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import modelsign
from modelsign.crypto.keys import (
    compute_fingerprint,
    generate_keypair,
    load_public_key,
    keyring_add,
    keyring_list,
    keyring_remove,
    load_private_key,
)
from modelsign.sig import read_sig
from modelsign.api import (
    TRUST_EMBEDDED,
    TRUST_PUBKEY,
    VerifyError,
    default_sig_path,
    sign_model,
    verify_model,
)

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
    if out_path is None:
        priv_path, _ = generate_keypair(DEFAULT_KEY_DIR)
    else:
        priv_path = Path(out_path).expanduser()
        if priv_path.exists():
            existing = compute_fingerprint(load_private_key(priv_path).public_key())
            click.echo(f"Key already exists: {priv_path}")
            click.echo(f"Fingerprint: {existing}")
            return

        pub_path = _expected_pubkey_path(priv_path)
        if pub_path.exists():
            click.echo(
                f"Error: {pub_path} already exists and belongs to another key. "
                "Choose a different name, or remove it first.",
                err=True,
            )
            sys.exit(1)

        priv_path.parent.mkdir(parents=True, exist_ok=True)
        if priv_path.name == "private.pem":
            generate_keypair(priv_path.parent)
        else:
            private_key = Ed25519PrivateKey.generate()
            priv_path.write_bytes(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            os.chmod(priv_path, 0o600)
            pub_path.write_bytes(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    fingerprint = compute_fingerprint(load_private_key(priv_path).public_key())
    click.echo(f"Private key: {priv_path}")
    click.echo(f"Public key:  {_find_pubkey_for_private(priv_path)}")
    click.echo(f"Fingerprint: {fingerprint}")


def _expected_pubkey_path(priv_path: Path) -> Path:
    """Where this private key's public half belongs.

    ``private.pem`` keeps the historical ``public.pem`` sibling. Any other
    name gets ``<stem>_public.pem``, so two keypairs in one directory cannot
    silently overwrite each other's public key — which is what happened
    before: the correct name was computed and then replaced by public.pem.
    """
    if priv_path.name == "private.pem":
        return priv_path.with_name("public.pem")
    return priv_path.with_name(priv_path.stem + "_public.pem")


def _find_pubkey_for_private(priv_path: Path) -> Path:
    """Locate the public key that actually belongs to this private key.

    Candidates are checked against the private key rather than taken on their
    filename, so a public.pem left by a different keypair is not reported as
    this one's.
    """
    expected = _expected_pubkey_path(priv_path)
    candidates = [
        expected,
        priv_path.with_name("public.pem"),
        priv_path.with_name(priv_path.stem + "_public.pem"),
    ]

    try:
        wanted = compute_fingerprint(load_private_key(priv_path).public_key())
    except Exception:
        wanted = None

    for candidate in candidates:
        if not candidate.exists():
            continue
        if wanted is None:
            return candidate
        try:
            if compute_fingerprint(load_public_key(candidate)) == wanted:
                return candidate
        except Exception:
            continue
    return expected


@main.command()
@click.argument("model_path")
@click.option("--name", default=None, help="Model name (required if --identity not given).")
@click.option("--identity", "identity_file", default=None, help="Path to JSON identity card file.")
@click.option("--key", "key_path", default=None, help="Path to private key PEM file.")
@click.option("--out", "out_path", default=None, help="Output .sig file path (default: MODEL.sig).")
@click.option(
    "--parent",
    "parent_sig",
    default=None,
    help="Signature of the model this was derived from; recorded as parent_signature.",
)
def sign(model_path, name, identity_file, key_path, out_path, parent_sig):
    """Sign a model file or directory."""
    model_path = Path(model_path)

    card = None
    if identity_file is not None:
        try:
            card = json.loads(Path(identity_file).read_text())
        except Exception as e:
            click.echo(f"Error reading identity file: {e}", err=True)
            sys.exit(1)
    elif name is None:
        click.echo("Error: provide --name or --identity.", err=True)
        sys.exit(1)

    sig_path = Path(out_path) if out_path else default_sig_path(model_path)

    try:
        sig = sign_model(
            model_path,
            card=card,
            name=name,
            key=key_path,
            sig_path=sig_path,
            parent=parent_sig,
        )
    except VerifyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        # Only validate_card raises ValueError now; key problems are VerifyError.
        click.echo(f"Error: invalid identity card: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Signed:      {model_path}")
    click.echo(f"Sig file:    {sig_path}")
    click.echo(f"Fingerprint: {sig.key_fingerprint}")
    click.echo(f"SHA-256:     {sig.sha256[:23]}...")
    if sig.identity.get("parent_signature"):
        click.echo(f"Parent:      {sig.identity['parent_signature'][:23]}...")


_TRUST_LABELS = {
    TRUST_PUBKEY: "TRUSTED (--pubkey)",
    TRUST_EMBEDDED: "UNVERIFIED — using embedded key, not independently trusted",
}

_FAILURE_LINES = {
    "hash mismatch": "Hash mismatch — file has been modified since signing.",
    "invalid signature": "Invalid signature — sig file may have been tampered with.",
}


@main.command()
@click.argument("model_path")
@click.option("--sig", "sig_path", default=None, help="Path to .sig file (default: MODEL.sig).")
@click.option("--pubkey", "pubkey_path", default=None, help="Path to trusted public key PEM.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output JSON.")
@click.option("--quiet", is_flag=True, default=False, help="Suppress output; use exit code only.")
@click.option(
    "--require-trusted",
    is_flag=True,
    default=False,
    help="Kept for compatibility; requiring a trusted key is now the default.",
)
@click.option(
    "--allow-embedded-key",
    is_flag=True,
    default=False,
    help="Accept a signature checkable only against its own key: integrity, not identity.",
)
@click.option(
    "--require-approval",
    "required_roles",
    multiple=True,
    help="Fail unless a trusted key approved in this role. Repeatable; all are required.",
)
@click.option(
    "--approver-key",
    "approver_keys",
    multiple=True,
    help="Public key PEM of an approver to trust, beyond the keyring. Repeatable.",
)
@click.option(
    "--min-approvals",
    default=0,
    type=int,
    help="Fail unless this many distinct trusted approvers signed off.",
)
@click.option(
    "--allow-unbound-name",
    is_flag=True,
    default=False,
    help="Accept a modelsign 1.x signature, which does not cover the filename.",
)
def verify(
    model_path, sig_path, pubkey_path, output_json, quiet, require_trusted,
    allow_embedded_key, required_roles, approver_keys, min_approvals,
    allow_unbound_name,
):
    """Verify a signed model file or directory."""
    model_path = Path(model_path)

    try:
        result = verify_model(
            model_path,
            sig_path=sig_path,
            pubkey=pubkey_path,
            require_trusted=not allow_embedded_key,
            require_name_binding=not allow_unbound_name,
        )
    except VerifyError as e:
        if not quiet:
            click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        if not quiet:
            click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    if not result.verified:
        if output_json:
            click.echo(json.dumps({
                "verified": False,
                "error": result.error,
                "detail": result.detail,
            }))
        elif not quiet:
            line = _FAILURE_LINES.get(result.error) or f"{result.error}: {result.detail}"
            click.echo(f"FAILED {model_path.name}\n  {line}", err=result.error == "corrupted sig")
        sys.exit(1)

    approvals = []
    if required_roles or min_approvals:
        from modelsign.approvals import ApprovalError, require_approval

        try:
            approvals = require_approval(
                sig_path or default_sig_path(model_path),
                roles=required_roles,
                count=min_approvals,
                pubkeys=list(approver_keys),
                keyring_dir=DEFAULT_KEY_DIR / "keyring",
            )
        except ApprovalError as e:
            if output_json:
                click.echo(json.dumps({"verified": False, "error": "approval", "detail": str(e)}))
            elif not quiet:
                click.echo(f"FAILED {model_path.name}\n  approval: {e}")
            sys.exit(1)

    trust_label = _TRUST_LABELS.get(result.trust) or f"TRUSTED (keyring: {result.trusted_alias})"

    if output_json:
        click.echo(json.dumps({
            "verified": True,
            "model": result.model,
            "sha256": result.sha256,
            "fingerprint": result.fingerprint,
            "trust": trust_label,
            "signed_at": result.signed_at,
            "identity": result.identity,
            "approvals": [
                {"role": a.role, "approver": a.approver, "key": a.key_fingerprint}
                for a in approvals
            ],
        }))
        return

    if quiet:
        return

    identity = result.identity
    click.echo(f"VERIFIED {model_path.name}")
    click.echo(f"  Name:         {identity.get('name', '(unnamed)')}")
    for label, field_name in (
        ("Creator", "creator"),
        ("Architecture", "architecture"),
        ("Base model", "base_model"),
        ("License", "license"),
    ):
        if identity.get(field_name):
            click.echo(f"  {label + ':':<13} {identity[field_name]}")
    click.echo(f"  Signed:       {result.signed_at} (unverified — no RFC 3161 timestamp)")
    click.echo(f"  Key:          {result.fingerprint} ({trust_label})")
    for approval in approvals:
        who = approval.approver or approval.trusted_alias or approval.key_fingerprint
        click.echo(f"  Approved:     {approval.role} — {who} ({approval.approved_at})")
    if not result.trusted:
        click.echo("  WARNING: key not in keyring. Run 'modelsign keyring add <pubkey> <alias>' to trust it.")




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


@main.group()
def oms():
    """Interoperate with OpenSSF Model Signing (OMS).

    OMS signatures are Sigstore bundles produced by the `model-signing`
    package. Signing uses ECDSA P-256 keys, because that verifier rejects
    Ed25519 — generate one with `modelsign oms keygen`.
    """


@oms.command("keygen")
@click.option("--dir", "key_dir", default=None, help="Where to write the keypair.")
def oms_keygen(key_dir):
    """Generate an ECDSA P-256 keypair for OMS signing."""
    from modelsign.oms import generate_ec_keypair

    priv, pub = generate_ec_keypair(Path(key_dir) if key_dir else DEFAULT_KEY_DIR)
    click.echo(f"Private key: {priv}")
    click.echo(f"Public key:  {pub}")


@oms.command("export")
@click.argument("model_path")
@click.option("--key", "key_path", required=True, help="ECDSA private key PEM.")
@click.option("--out", default=None, help="Bundle path (default: model.sig beside the model).")
@click.option("--name", default=None, help="Model name recorded in the statement.")
@click.option("--allow-symlinks", is_flag=True, default=False, help="Follow symlinks.")
def oms_export(model_path, key_path, out, name, allow_symlinks):
    """Sign a model into an OMS bundle any OMS verifier can read."""
    from modelsign.oms import DEFAULT_BUNDLE_NAME, OMSError, export_bundle

    try:
        export_bundle(
            model_path,
            key=key_path,
            name=name,
            out=out,
            allow_symlinks=allow_symlinks,
        )
    except (OMSError, VerifyError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    bundle = out or str(Path(model_path).parent / DEFAULT_BUNDLE_NAME)
    click.echo(f"Signed:  {model_path}")
    click.echo(f"Bundle:  {bundle}")
    click.echo("Format:  OpenSSF Model Signing (sigstore bundle, DSSE, in-toto)")


@oms.command("verify")
@click.argument("model_path")
@click.option("--bundle", "bundle_path", default=None, help="Bundle path (default: model.sig).")
@click.option("--pubkey", "pubkey_path", required=True, help="ECDSA public key PEM.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output JSON.")
@click.option("--quiet", is_flag=True, default=False, help="Exit code only.")
def oms_verify(model_path, bundle_path, pubkey_path, output_json, quiet):
    """Verify a model against an OMS bundle."""
    from modelsign.oms import DEFAULT_BUNDLE_NAME, OMSError, verify_bundle

    model_path = Path(model_path)
    bundle = Path(bundle_path) if bundle_path else model_path / DEFAULT_BUNDLE_NAME
    if not bundle.exists() and not bundle_path:
        bundle = model_path.parent / DEFAULT_BUNDLE_NAME

    try:
        result = verify_bundle(model_path, bundle, pubkey=pubkey_path)
    except (OMSError, VerifyError) as e:
        if not quiet:
            click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    if output_json:
        click.echo(json.dumps({
            "verified": result.verified,
            "model": result.model,
            "sha256": result.sha256,
            "error": result.error,
            "detail": result.detail,
            "identity": result.identity,
        }))
    elif not quiet:
        if result.verified:
            click.echo(f"VERIFIED {model_path.name}")
            click.echo(f"  Name:    {result.identity.get('name')}")
            click.echo("  Format:  OpenSSF Model Signing")
            click.echo(f"  Digest:  {result.sha256}")
        else:
            click.echo(f"FAILED {model_path.name}\n  {result.error}: {result.detail}")

    sys.exit(0 if result.verified else 1)


@main.command()
@click.argument("model_path")
@click.option("--sig", "sig_path", default=None, help="Path to .sig file (default: MODEL.sig).")
@click.option(
    "--search",
    multiple=True,
    help="Directory (or .sig file) to search for ancestor signatures. Repeatable.",
)
@click.option("--pubkey", "pubkey_path", default=None, help="Trusted public key PEM.")
@click.option(
    "--require-complete",
    is_flag=True,
    default=False,
    help="Fail unless the chain reaches a model that records no parent.",
)
@click.option("--json", "output_json", is_flag=True, default=False, help="Output JSON.")
def lineage(model_path, sig_path, search, pubkey_path, require_complete, output_json):
    """Walk a model's provenance chain back through its ancestors."""
    from modelsign.lineage import verify_lineage

    result = verify_lineage(
        model_path,
        sig_path=sig_path,
        search=search,
        pubkey=pubkey_path,
        require_complete=require_complete,
    )

    if output_json:
        click.echo(json.dumps({
            "verified": result.verified,
            "complete": result.complete,
            "depth": result.depth,
            "error": result.error,
            "chain": [
                {
                    "depth": link.depth,
                    "name": link.name,
                    "digest": link.digest,
                    "sig": str(link.sig_path) if link.sig_path else None,
                    "signature_valid": link.signature_valid,
                    "bytes_verified": link.bytes_verified,
                    "key": link.key_fingerprint,
                    "error": link.error,
                }
                for link in result.chain
            ],
        }))
        sys.exit(0 if result.verified else 1)

    header = "LINEAGE VERIFIED" if result.verified else "LINEAGE FAILED"
    click.echo(f"{header} {Path(model_path).name}  ({result.depth} link(s))")
    for link in result.chain:
        mark = "ok " if link.ok else "BAD"
        indent = "  " + ("  " * link.depth)
        label = link.name or "(unnamed)"
        click.echo(f"{indent}[{mark}] {label}")
        if link.digest:
            click.echo(f"{indent}      sig {link.digest[:23]}...")
        if link.key_fingerprint:
            scope = "bytes + signature" if link.bytes_verified else "signature only"
            click.echo(f"{indent}      key {link.key_fingerprint} ({scope})")
        if link.error:
            click.echo(f"{indent}      {link.error}")
    if not result.complete and result.verified:
        click.echo("  chain incomplete — an ancestor signature was not among those searched")
    if result.error:
        click.echo(f"  {result.error}")

    sys.exit(0 if result.verified else 1)


@main.command()
@click.argument("model_path")
@click.option("--key", "key_path", default=None, help="Private key PEM of the approver.")
@click.option("--role", required=True, help="What is being approved, e.g. 'release-manager'.")
@click.option("--approver", default="", help="Who is approving, for the record.")
@click.option("--sig", "sig_path", default=None, help="Path to .sig file (default: MODEL.sig).")
def approve(model_path, key_path, role, approver, sig_path):
    """Countersign a model's signature as an approver.

    An approval is appended to the .sig and signed over that signature's
    digest, so it cannot be moved to another model. Note that the model's own
    signature does not cover approvals: removing one leaves no trace, so a
    verifier has to require the approvals it wants with --require-approval.
    """
    from modelsign.approvals import ApprovalError, approve as add_approval

    try:
        approval = add_approval(
            model_path,
            key=key_path or (DEFAULT_KEY_DIR / "private.pem"),
            role=role,
            approver=approver,
            sig_path=sig_path,
        )
    except (ApprovalError, VerifyError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Approved:    {model_path}")
    click.echo(f"Role:        {approval.role}")
    if approval.approver:
        click.echo(f"Approver:    {approval.approver}")
    click.echo(f"Key:         {approval.key_fingerprint}")
    click.echo(f"At:          {approval.approved_at}")
