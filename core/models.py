"""Shared immutable result objects used by core inspection modules."""

from dataclasses import dataclass
from enum import Enum


class MetadataStatus(str, Enum):
    PRESENT = "Present"
    MISSING = "Missing"
    INVALID = "Invalid"
    UNSUPPORTED = "Unsupported"
    UNAVAILABLE = "Unavailable"


@dataclass(frozen=True)
class ImageProperties:
    filename: str
    file_size_bytes: int
    image_format: str
    mime_type: str
    width: int
    height: int
    aspect_ratio: float
    megapixels: float
    color_mode: str
    bit_depth_per_channel: int | None
    frame_count: int
    has_transparency: bool
    extension_mismatch: bool


@dataclass(frozen=True)
class MetadataField:
    key: str
    label: str
    value: str | None
    status: MetadataStatus
    source: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class ImageInspection:
    properties: ImageProperties
    metadata: tuple[MetadataField, ...]
    sha256: str
    warnings: tuple[str, ...] = ()
