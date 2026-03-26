"""Streaming SHA-256 hash for single model files."""

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MB


def hash_file(path: Path) -> str:
    """Compute SHA-256 hash of a file using streaming reads.

    Returns hex digest string (64 chars).
    Raises FileNotFoundError if path doesn't exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
