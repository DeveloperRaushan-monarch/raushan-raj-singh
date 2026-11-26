"""Structured extraction of common EXIF fields with explicit field statuses."""

from io import BytesIO
from datetime import datetime
import struct
from typing import Any

import exifread
from PIL import ExifTags, Image

from core.models import MetadataField, MetadataStatus


FIELD_SPECS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("make", "Camera make", ("Image Make", "Make"), "text"),
    ("model", "Camera model", ("Image Model", "Model"), "text"),
    (
        "datetime_original",
        "Capture date and time",
        ("EXIF DateTimeOriginal", "DateTimeOriginal", "Image DateTime", "DateTime"),
        "datetime",
    ),
    ("software", "Editing software", ("Image Software", "Software"), "text"),
    ("exposure_time", "Exposure time", ("EXIF ExposureTime", "ExposureTime"), "positive"),
    ("aperture", "Aperture", ("EXIF FNumber", "FNumber"), "positive"),
    (
        "iso",
        "ISO",
        ("EXIF ISOSpeedRatings", "EXIF PhotographicSensitivity", "ISOSpeedRatings", "PhotographicSensitivity"),
        "positive_integer",
    ),
    ("focal_length", "Focal length", ("EXIF FocalLength", "FocalLength"), "positive"),
    ("orientation", "Orientation", ("Image Orientation", "Orientation"), "orientation"),
    ("flash", "Flash", ("EXIF Flash", "Flash"), "text"),
    ("color_space", "Color space", ("EXIF ColorSpace", "ColorSpace"), "text"),
)

EXIF_CAPABLE_FORMATS = {"JPEG", "PNG", "WEBP", "TIFF"}


def _clean_value(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "printable"):
        value = value.printable
    result = " ".join(str(value).strip().split())
    return result or None


def _parse_fraction(value: str) -> float | None:
    try:
        if "/" in value:
            numerator, denominator = value.split("/", 1)
            denominator_value = float(denominator.strip())
            if denominator_value == 0:
                return None
            return float(numerator.strip()) / denominator_value
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _is_valid(value: str, kind: str) -> bool:
    if kind == "text":
        return bool(value.strip())
    if kind == "datetime":
        normalized = value.strip()
        for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                datetime.strptime(normalized[:19], pattern)
                return True
            except ValueError:
                continue
        return False
    if kind == "orientation":
        parsed = _parse_fraction(value)
        return parsed is not None and parsed.is_integer() and 1 <= parsed <= 8
    if kind == "positive_integer":
        parsed = _parse_fraction(value)
        return parsed is not None and parsed.is_integer() and parsed > 0
    if kind == "positive":
        parsed = _parse_fraction(value)
        return parsed is not None and parsed > 0
    return True


def _read_exif_tags(file_bytes: bytes) -> tuple[dict[str, str], bool]:
    values: dict[str, str] = {}
    exifread_succeeded = False
    pillow_succeeded = False
    try:
        tags = exifread.process_file(BytesIO(file_bytes), details=False, strict=False)
        exifread_succeeded = True
        for key, value in tags.items():
            cleaned = _clean_value(value)
            if cleaned is not None:
                values[str(key)] = cleaned
    except (OSError, EOFError, ValueError, TypeError, IndexError, struct.error):
        pass

    # Pillow supplies EXIF for additional containers (including PNG/WebP) and
    # acts as a fallback when ExifRead does not recognize a container's EXIF.
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            exif = image.getexif()
            pillow_succeeded = True
            pil_tags = dict(exif.items())
            try:
                pil_tags.update(exif.get_ifd(ExifTags.IFD.Exif))
            except (AttributeError, KeyError, TypeError):
                pass
            for tag_id, value in pil_tags.items():
                name = ExifTags.TAGS.get(tag_id)
                cleaned = _clean_value(value)
                if name and cleaned is not None:
                    values.setdefault(str(name), cleaned)
    except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return values, exifread_succeeded or pillow_succeeded


def extract_metadata(file_bytes: bytes, image_format: str) -> tuple[MetadataField, ...]:
    """Extract common EXIF fields; mark unsupported/unavailable data honestly."""
    tags, parser_available = _read_exif_tags(file_bytes)
    fields: list[MetadataField] = []
    is_exif_capable = image_format.upper() in EXIF_CAPABLE_FORMATS

    for key, label, aliases, validation_kind in FIELD_SPECS:
        value = next((tags[alias] for alias in aliases if alias in tags), None)
        if not is_exif_capable:
            status = MetadataStatus.UNSUPPORTED
            note = "EXIF extraction is not supported for this image format."
        elif not parser_available:
            status = MetadataStatus.UNAVAILABLE
            note = "The metadata parser could not read this image's metadata."
        elif value is None:
            status = MetadataStatus.MISSING
            note = None
        elif not _is_valid(value, validation_kind):
            status = MetadataStatus.INVALID
            note = "The stored value does not match the expected format or range."
        else:
            status = MetadataStatus.PRESENT
            note = None
        fields.append(
            MetadataField(
                key=key,
                label=label,
                value=value,
                status=status,
                source="EXIF" if value is not None else None,
                note=note,
            )
        )

    for key, label in (("xmp", "XMP metadata"), ("iptc", "IPTC metadata")):
        fields.append(
            MetadataField(
                key=key,
                label=label,
                value=None,
                status=MetadataStatus.UNSUPPORTED,
                note="XMP/IPTC parsing is not implemented in Phase 1.",
            )
        )
    return tuple(fields)
