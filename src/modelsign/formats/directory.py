"""Directory manifest hashing for multi-file models."""

import hashlib
from pathlib import Path

from modelsign.formats.single import hash_file
from modelsign.identity.canonical import canonical_json


def hash_directory(path: Path) -> tuple[dict, str]:
    """Hash all files in a directory, return (manifest_dict, manifest_hash).

    Files are sorted by UTF-8 byte order (NOT locale-aware) for
    deterministic results across Linux/macOS/Windows.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {path}")

    all_files = [f for f in path.rglob("*") if f.is_file()]
    all_files.sort(key=lambda f: str(f.relative_to(path)).encode("utf-8"))

    files_dict = {}
    for file_path in all_files:
        rel_path = str(file_path.relative_to(path))
        file_hash = hash_file(file_path)
        files_dict[rel_path] = f"sha256:{file_hash}"

    manifest = {"files": files_dict}
    manifest_bytes = canonical_json(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    return manifest, manifest_hash
