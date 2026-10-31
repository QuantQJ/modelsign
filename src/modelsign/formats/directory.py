"""Directory manifest hashing for multi-file models."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable

from modelsign.formats.single import hash_file
from modelsign.identity.canonical import canonical_json

#: Hash files concurrently above this count. Below it, the thread pool costs
#: more than it saves.
PARALLEL_THRESHOLD = 2


def _workers(file_count: int) -> int:
    return max(1, min(file_count, (os.cpu_count() or 1)))


def hash_directory(
    path: Path,
    max_workers: int | None = None,
    exclude: Iterable[str] = (),
) -> tuple[dict, str]:
    """Hash all files in a directory, return (manifest_dict, manifest_hash).

    Files are sorted by UTF-8 byte order (NOT locale-aware) for
    deterministic results across Linux/macOS/Windows.

    ``exclude`` holds relative POSIX paths to leave out — used for a signature
    stored inside the directory it signs, which cannot be part of its own
    manifest. Nothing is excluded by default, so a signature made before this
    existed still verifies.

    Files are hashed concurrently — SHA-256 of one file is inherently
    sequential, but a sharded model is many files, and hashlib releases the
    GIL while it works. The manifest does not depend on the order in which
    they finish.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {path}")

    skip = set(exclude)
    all_files = [
        f for f in path.rglob("*")
        if f.is_file() and f.relative_to(path).as_posix() not in skip
    ]
    all_files.sort(key=lambda f: str(f.relative_to(path)).encode("utf-8"))

    workers = max_workers if max_workers is not None else _workers(len(all_files))
    if len(all_files) >= PARALLEL_THRESHOLD and workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            digests = list(pool.map(hash_file, all_files))
    else:
        digests = [hash_file(f) for f in all_files]

    files_dict = {
        str(file_path.relative_to(path)): f"sha256:{digest}"
        for file_path, digest in zip(all_files, digests)
    }

    manifest = {"files": files_dict}
    manifest_bytes = canonical_json(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    return manifest, manifest_hash
