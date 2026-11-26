import hashlib

import pytest

from core.hashing import calculate_sha256


def test_hash_matches_standard_sha256_for_original_bytes():
    original = b"pixeltruth-original-file-bytes"
    assert calculate_sha256(original) == hashlib.sha256(original).hexdigest()


def test_hash_requires_bytes():
    with pytest.raises(TypeError):
        calculate_sha256("not bytes")
