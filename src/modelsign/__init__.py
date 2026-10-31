"""modelsign — Sign AI models with identity. Verify anywhere."""

__version__ = "1.1.0"

from modelsign.identity.card import ModelCard, validate_card
from modelsign.identity.canonical import canonical_json
from modelsign.crypto.keys import generate_keypair, load_private_key, load_public_key, compute_fingerprint
from modelsign.crypto.sign import sign_bytes, build_file_message, build_dir_message
from modelsign.crypto.verify import verify_bytes
from modelsign.formats.single import hash_file
from modelsign.formats.directory import hash_directory
from modelsign.sig import SigFile, write_sig, read_sig

from modelsign.api import (
    TRUST_EMBEDDED,
    TRUST_KEYRING,
    TRUST_PUBKEY,
    VerifyError,
    VerifyResult,
    sign_model,
    verify_model,
)

__all__ = [
    "__version__",
    # High-level API — what callers should reach for first.
    "sign_model", "verify_model", "VerifyResult", "VerifyError",
    "TRUST_PUBKEY", "TRUST_KEYRING", "TRUST_EMBEDDED",
    # Building blocks.
    "ModelCard", "validate_card", "canonical_json",
    "generate_keypair", "load_private_key", "load_public_key", "compute_fingerprint",
    "sign_bytes", "build_file_message", "build_dir_message", "verify_bytes",
    "hash_file", "hash_directory",
    "SigFile", "write_sig", "read_sig",
]
