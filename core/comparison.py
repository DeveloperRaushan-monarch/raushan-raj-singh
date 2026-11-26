"""Pairwise file and image comparisons with a limited sampled pixel indicator."""

from dataclasses import dataclass
from io import BytesIO

import numpy as np
from PIL import Image, ImageOps

from core.analysis import inspect_image
from core.models import ImageInspection


@dataclass(frozen=True)
class ComparisonMetric:
    label: str
    reference_value: str
    suspect_value: str
    matches: bool


@dataclass(frozen=True)
class ComparisonResult:
    reference: ImageInspection
    suspect: ImageInspection
    metrics: tuple[ComparisonMetric, ...]
    metadata_differences: tuple[ComparisonMetric, ...]
    hashes_match: bool
    sampled_pixel_similarity: float | None
    similarity_note: str


def _format_size(size: int) -> str:
    return f"{size / (1024 * 1024):.2f} MB"


def _sample_rgb(file_bytes: bytes) -> tuple[Image.Image, tuple[int, int]]:
    with Image.open(BytesIO(file_bytes)) as opened:
        opened.seek(0)
        oriented = ImageOps.exif_transpose(opened)
        rgb = oriented.convert("RGB")
        display_size = rgb.size
        rgb.thumbnail((512, 512), Image.Resampling.LANCZOS)
        return rgb.copy(), display_size


def _sampled_similarity(reference_bytes: bytes, suspect_bytes: bytes) -> tuple[float | None, str]:
    reference, reference_size = _sample_rgb(reference_bytes)
    suspect, suspect_size = _sample_rgb(suspect_bytes)
    if reference_size != suspect_size:
        return None, "Not calculated because orientation-adjusted dimensions differ."
    reference_pixels = np.asarray(reference, dtype=np.int16)
    suspect_pixels = np.asarray(suspect, dtype=np.int16)
    mean_absolute_difference = float(np.abs(reference_pixels - suspect_pixels).mean())
    score = 1.0 - mean_absolute_difference / 255.0
    return score, (
        "Normalized mean absolute RGB difference on images sampled to at most 512 × 512. "
        "This is a descriptive indicator, not SSIM or proof of common origin/authenticity."
    )


def compare_images(
    reference_bytes: bytes,
    reference_name: str,
    suspect_bytes: bytes,
    suspect_name: str,
) -> ComparisonResult:
    """Validate both files, compare properties/metadata/hashes, and sample pixels."""
    reference = inspect_image(reference_bytes, reference_name)
    suspect = inspect_image(suspect_bytes, suspect_name)
    a = reference.properties
    b = suspect.properties
    metrics = (
        ComparisonMetric("Format", a.image_format, b.image_format, a.image_format == b.image_format),
        ComparisonMetric("File size", _format_size(a.file_size_bytes), _format_size(b.file_size_bytes), a.file_size_bytes == b.file_size_bytes),
        ComparisonMetric("Dimensions", f"{a.width} × {a.height}", f"{b.width} × {b.height}", (a.width, a.height) == (b.width, b.height)),
        ComparisonMetric("Colour mode", a.color_mode, b.color_mode, a.color_mode == b.color_mode),
        ComparisonMetric("SHA-256", reference.sha256, suspect.sha256, reference.sha256 == suspect.sha256),
    )

    reference_fields = {field.key: field for field in reference.metadata}
    suspect_fields = {field.key: field for field in suspect.metadata}
    metadata_differences: list[ComparisonMetric] = []
    for key in reference_fields.keys() | suspect_fields.keys():
        left = reference_fields.get(key)
        right = suspect_fields.get(key)
        left_value = f"{left.status.value}: {left.value or 'Not available'}" if left else "Unavailable"
        right_value = f"{right.status.value}: {right.value or 'Not available'}" if right else "Unavailable"
        if left_value != right_value:
            label = (left or right).label  # type: ignore[union-attr]
            metadata_differences.append(
                ComparisonMetric(label, left_value, right_value, False)
            )

    pixel_similarity, note = _sampled_similarity(reference_bytes, suspect_bytes)
    return ComparisonResult(
        reference=reference,
        suspect=suspect,
        metrics=metrics,
        metadata_differences=tuple(sorted(metadata_differences, key=lambda item: item.label)),
        hashes_match=reference.sha256 == suspect.sha256,
        sampled_pixel_similarity=pixel_similarity,
        similarity_note=note,
    )
