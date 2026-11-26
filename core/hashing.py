"""Cryptographic fingerprints for original uploaded byte sequences."""

import hashlib


def calculate_sha256(file_bytes: bytes) -> str:
    """Return the SHA-256 digest of the exact supplied bytes."""
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")
    return hashlib.sha256(file_bytes).hexdigest()
