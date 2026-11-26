"""Explicit, on-demand extraction of GPS tags from image EXIF."""

from dataclasses import dataclass
from datetime import date
from io import BytesIO
import struct

import exifread
from PIL import ExifTags, Image

from core.models import MetadataStatus


@dataclass(frozen=True)
class GPSResult:
    status: MetadataStatus
    latitude: float | None = None
    longitude: float | None = None
    altitude_meters: float | None = None
    timestamp_utc: str | None = None
    note: str | None = None


def _number(value: object) -> float | None:
    numerator = getattr(value, "num", None)
    denominator = getattr(value, "den", None)
    if numerator is not None and denominator is not None:
        if denominator == 0:
            return None
        return float(numerator) / float(denominator)
    numerator = getattr(value, "numerator", None)
    denominator = getattr(value, "denominator", None)
    if numerator is not None and denominator is not None:
        if denominator == 0:
            return None
        return float(numerator) / float(denominator)
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _tag_text(value: object | None) -> str | None:
    if value is None:
        return None
    printable = getattr(value, "printable", value)
    return str(printable).strip().upper() or None


def _coordinate(values: object, reference: object, *, latitude: bool) -> float | None:
    if not isinstance(values, (list, tuple)) or len(values) != 3:
        return None
    parts = [_number(value) for value in values]
    if any(part is None for part in parts):
        return None
    degrees, minutes, seconds = (float(part) for part in parts if part is not None)
    if minutes >= 60 or seconds >= 60:
        return None
    maximum = 90 if latitude else 180
    if degrees > maximum or (degrees == maximum and (minutes != 0 or seconds != 0)):
        return None
    ref = _tag_text(reference)
    valid_refs = {"N", "S"} if latitude else {"E", "W"}
    if ref not in valid_refs:
        return None
    decimal = degrees + minutes / 60 + seconds / 3600
    return -decimal if ref in {"S", "W"} else decimal


def extract_gps(file_bytes: bytes, image_format: str | None = None) -> GPSResult:
    """Read GPS only when called by an explicit user action; never log values."""
    tags: dict[str, object] = {}
    parser_available = False
    detected_format = image_format.upper() if image_format else ""
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            detected_format = detected_format or (image.format or "").upper()
            parser_available = True
            try:
                gps_ifd = image.getexif().get_ifd(ExifTags.IFD.GPSInfo)
                for tag_id, value in gps_ifd.items():
                    tag_name = ExifTags.GPSTAGS.get(tag_id)
                    if tag_name:
                        tags[f"GPS {tag_name}"] = value
            except (AttributeError, KeyError, TypeError):
                pass
    except (OSError, EOFError, ValueError, TypeError):
        pass

    if detected_format not in {"JPEG", "PNG", "WEBP", "TIFF"}:
        return GPSResult(
            status=MetadataStatus.UNSUPPORTED,
            note="GPS extraction is unsupported for this image format.",
        )

    if detected_format in {"JPEG", "TIFF"}:
        try:
            exif_tags = exifread.process_file(BytesIO(file_bytes), details=False, strict=False)
            parser_available = True
            tags.update(exif_tags)
        except (OSError, EOFError, ValueError, TypeError, IndexError, struct.error):
            pass
    if not parser_available:
        return GPSResult(
            status=MetadataStatus.UNAVAILABLE,
            note="GPS metadata could not be read from this image.",
        )

    latitude_tag = tags.get("GPS GPSLatitude")
    longitude_tag = tags.get("GPS GPSLongitude")
    latitude_ref = tags.get("GPS GPSLatitudeRef")
    longitude_ref = tags.get("GPS GPSLongitudeRef")
    if not any((latitude_tag, longitude_tag, latitude_ref, longitude_ref)):
        return GPSResult(status=MetadataStatus.MISSING, note="No GPS coordinates were found.")

    latitude_values = getattr(latitude_tag, "values", latitude_tag)
    longitude_values = getattr(longitude_tag, "values", longitude_tag)
    latitude = _coordinate(latitude_values or (), latitude_ref, latitude=True) if latitude_tag else None
    longitude = _coordinate(longitude_values or (), longitude_ref, latitude=False) if longitude_tag else None
    if latitude is None or longitude is None:
        return GPSResult(
            status=MetadataStatus.INVALID,
            note="GPS tags are present but incomplete or outside valid coordinate ranges.",
        )

    altitude = None
    altitude_tag = tags.get("GPS GPSAltitude")
    if altitude_tag:
        altitude_values = getattr(altitude_tag, "values", altitude_tag)
        if not isinstance(altitude_values, (tuple, list)):
            altitude_values = (altitude_values,)
        altitude = _number(altitude_values[0]) if altitude_values else None
        altitude_ref = tags.get("GPS GPSAltitudeRef")
        if altitude is not None and altitude_ref:
            ref_values = getattr(altitude_ref, "values", altitude_ref)
            if not isinstance(ref_values, (tuple, list)):
                ref_values = (ref_values,)
            if ref_values and _number(ref_values[0]) == 1:
                altitude = -altitude

    timestamp = None
    date_tag = tags.get("GPS GPSDate") or tags.get("GPS GPSDateStamp")
    time_tag = tags.get("GPS GPSTimeStamp")
    if date_tag and time_tag:
        date_text = _tag_text(date_tag)
        time_values = getattr(time_tag, "values", time_tag)
        time_parts = [_number(item) for item in time_values]
        if date_text and len(time_parts) == 3 and all(item is not None for item in time_parts):
            try:
                parsed_date = date.fromisoformat(date_text.replace(":", "-", 2))
                hour, minute, second = (int(float(item)) for item in time_parts if item is not None)
                if hour < 24 and minute < 60 and second < 60:
                    timestamp = f"{parsed_date.isoformat()} {hour:02d}:{minute:02d}:{second:02d} UTC"
            except ValueError:
                timestamp = None

    return GPSResult(
        status=MetadataStatus.PRESENT,
        latitude=latitude,
        longitude=longitude,
        altitude_meters=altitude,
        timestamp_utc=timestamp,
    )
