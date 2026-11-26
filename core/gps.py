"""Explicit, on-demand extraction of GPS tags from image EXIF."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from io import BytesIO
import math
import re
import struct
import xml.etree.ElementTree as ET

import exifread
from PIL import ExifTags, Image

from core.models import MetadataStatus
from core.xmp import _image_xmp


@dataclass(frozen=True)
class GPSResult:
    status: MetadataStatus
    latitude: float | None = None
    longitude: float | None = None
    altitude_meters: float | None = None
    timestamp_utc: str | None = None
    note: str | None = None
    gps_state: str = "NO_GPS_METADATA"
    raw_tags: tuple[tuple[str, str], ...] = ()
    extra_properties: tuple[tuple[str, str], ...] = ()


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    numerator = getattr(value, "num", None)
    denominator = getattr(value, "den", None)
    if numerator is not None and denominator is not None:
        if denominator == 0:
            return None
        val = float(numerator) / float(denominator)
        return val if math.isfinite(val) else None
    numerator = getattr(value, "numerator", None)
    denominator = getattr(value, "denominator", None)
    if numerator is not None and denominator is not None:
        if denominator == 0:
            return None
        val = float(numerator) / float(denominator)
        return val if math.isfinite(val) else None
    try:
        val = float(value)  # type: ignore[arg-type]
        return val if math.isfinite(val) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _tag_text(value: object | None) -> str | None:
    if value is None:
        return None
    printable = getattr(value, "printable", value)
    if isinstance(printable, (bytes, bytearray)):
        text = bytes(printable).decode("ascii", errors="ignore")
    else:
        text = str(printable)
    cleaned = text.replace("\x00", "").strip().upper()
    return cleaned or None


def _format_raw_tag(value: object) -> str:
    printable = getattr(value, "printable", None)
    if printable is not None:
        return " ".join(str(printable).replace("\x00", "").strip().split())
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if raw.startswith((b"ASCII\x00\x00\x00", b"UNICODE\x00")):
            return raw[8:].decode("utf-8", errors="replace").replace("\x00", "").strip()
        try:
            decoded = raw.decode("ascii").replace("\x00", "").strip()
            if decoded and decoded.isprintable():
                return decoded
        except UnicodeDecodeError:
            pass
        return "0x" + raw[:32].hex()
    if isinstance(value, (list, tuple)):
        return ", ".join(_format_raw_tag(v) for v in value)
    return " ".join(str(value).replace("\x00", "").strip().split())


def _coordinate(values: object, reference: object, *, latitude: bool) -> float | None:
    maximum = 90.0 if latitude else 180.0
    ref = _tag_text(reference)
    valid_refs = {"N", "S"} if latitude else {"E", "W"}
    if ref not in valid_refs:
        return None

    # Handle single decimal coordinate (scalar or 1-element tuple/list)
    if isinstance(values, (list, tuple)) and len(values) == 1:
        values = values[0]
    if not isinstance(values, (list, tuple)):
        dec = _number(values)
        if dec is None or dec < 0.0 or dec > maximum:
            return None
        return -dec if ref in {"S", "W"} else dec

    if len(values) != 3:
        return None
    parts = [_number(value) for value in values]
    if any(part is None for part in parts):
        return None
    degrees, minutes, seconds = (float(part) for part in parts if part is not None)
    if degrees < 0 or minutes < 0 or seconds < 0:
        return None
    if minutes >= 60 or seconds >= 60:
        return None
    if degrees > maximum or (degrees == maximum and (minutes != 0 or seconds != 0)):
        return None
    decimal = degrees + minutes / 60.0 + seconds / 3600.0
    return -decimal if ref in {"S", "W"} else decimal


_COORDINATE_TAG_KEYS = {
    "GPS GPSLatitude",
    "GPS GPSLongitude",
    "GPS GPSLatitudeRef",
    "GPS GPSLongitudeRef",
    "GPS GPSAltitude",
    "GPS GPSAltitudeRef",
    "GPS GPSDate",
    "GPS GPSDateStamp",
    "GPS GPSTimeStamp",
}


def _parse_xmp_coordinate(raw: str, *, latitude: bool) -> float | None:
    """Parse XMP GPS coordinate strings such as '37,48.5N', '37,48,30N', or '-122.404'."""
    text = raw.strip()
    if not text:
        return None
    maximum = 90.0 if latitude else 180.0
    valid_refs = {"N", "S"} if latitude else {"E", "W"}
    ref = text[-1].upper() if text[-1].upper() in valid_refs else None
    body = text[:-1].strip() if ref else text

    # Comma-separated XMP DMS/DM format: "37,48.5" or "37,48,30"
    if "," in body:
        parts = [p.strip() for p in body.split(",") if p.strip()]
        if len(parts) == 2:
            deg = _number(parts[0])
            mins = _number(parts[1])
            if deg is None or mins is None or deg < 0 or mins < 0 or mins >= 60 or ref is None:
                return None
            val = deg + mins / 60.0
            if val > maximum:
                return None
            return -val if ref in {"S", "W"} else val
        if len(parts) == 3:
            deg = _number(parts[0])
            mins = _number(parts[1])
            secs = _number(parts[2])
            if deg is None or mins is None or secs is None:
                return None
            if deg < 0 or mins < 0 or secs < 0 or mins >= 60 or secs >= 60 or ref is None:
                return None
            val = deg + mins / 60.0 + secs / 3600.0
            if val > maximum:
                return None
            return -val if ref in {"S", "W"} else val
        return None

    dec = _number(body)
    if dec is None:
        return None
    if ref is not None:
        if dec < 0 or dec > maximum:
            return None
        return -dec if ref in {"S", "W"} else dec
    if abs(dec) > maximum:
        return None
    return dec


def _extract_xmp_gps(file_bytes: bytes, image_format: str) -> GPSResult | None:
    """Fallback extraction of GPS coordinates stored in XMP packets."""
    try:
        packet = _image_xmp(file_bytes, image_format)
    except Exception:
        return None
    if not packet:
        return None
    lowered = packet.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return None
    try:
        root = ET.fromstring(packet.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return None

    xmp_gps: dict[str, str] = {}
    for elem in root.iter():
        for attr_k, attr_v in elem.attrib.items():
            local = attr_k.split("}", 1)[-1]
            if local.lower().startswith("gps") and attr_v.strip():
                xmp_gps.setdefault(local, attr_v.strip())
        local = elem.tag.split("}", 1)[-1]
        if local.lower().startswith("gps") and (elem.text or "").strip():
            xmp_gps.setdefault(local, (elem.text or "").strip())

    if not xmp_gps:
        return None

    raw_pairs = tuple((f"XMP:{k}", v) for k, v in sorted(xmp_gps.items()))
    lat_str = xmp_gps.get("GPSLatitude")
    lon_str = xmp_gps.get("GPSLongitude")
    if not lat_str and not lon_str:
        return GPSResult(
            status=MetadataStatus.MISSING,
            note="XMP GPS tags are present, but no GPS coordinates were found in this image.",
            gps_state="GPS_METADATA_PRESENT",
            raw_tags=raw_pairs,
        )
    if not lat_str or not lon_str:
        return GPSResult(
            status=MetadataStatus.INVALID,
            note="XMP GPS tags are present, but latitude or longitude is incomplete.",
            gps_state="GPS_COORDINATES_INCOMPLETE",
            raw_tags=raw_pairs,
        )
    lat = _parse_xmp_coordinate(lat_str, latitude=True)
    lon = _parse_xmp_coordinate(lon_str, latitude=False)
    if lat is None or lon is None:
        return GPSResult(
            status=MetadataStatus.INVALID,
            note="XMP GPS tags are present, but coordinate values are invalid or outside valid ranges.",
            gps_state="GPS_COORDINATES_INVALID",
            raw_tags=raw_pairs,
        )

    alt = None
    if "GPSAltitude" in xmp_gps:
        alt_raw = xmp_gps["GPSAltitude"]
        if "/" in alt_raw:
            num_s, _, den_s = alt_raw.partition("/")
            num_v, den_v = _number(num_s), _number(den_s)
            if num_v is not None and den_v not in (None, 0.0):
                alt = num_v / den_v
        else:
            alt = _number(alt_raw)
        if alt is not None and xmp_gps.get("GPSAltitudeRef") == "1":
            alt = -alt

    return GPSResult(
        status=MetadataStatus.PRESENT,
        latitude=lat,
        longitude=lon,
        altitude_meters=alt,
        gps_state="GPS_COORDINATES_AVAILABLE",
        raw_tags=raw_pairs,
    )


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
                    tag_name = ExifTags.GPSTAGS.get(tag_id, f"Tag0x{int(tag_id):04X}")
                    tags[f"GPS {tag_name}"] = value
            except (AttributeError, KeyError, TypeError):
                pass
    except (OSError, EOFError, ValueError, TypeError):
        pass

    if detected_format not in {"JPEG", "PNG", "WEBP", "TIFF"}:
        return GPSResult(
            status=MetadataStatus.UNSUPPORTED,
            note="GPS extraction is unsupported for this image format.",
            gps_state="NO_GPS_METADATA",
        )

    if detected_format in {"JPEG", "TIFF"}:
        try:
            exif_tags = exifread.process_file(BytesIO(file_bytes), details=False, strict=False)
            parser_available = True
            for key, val in exif_tags.items():
                if key.startswith("GPS ") and key not in tags:
                    tags[key] = val
        except (OSError, EOFError, ValueError, TypeError, IndexError, struct.error):
            pass

    if not parser_available:
        return GPSResult(
            status=MetadataStatus.UNAVAILABLE,
            note="GPS metadata could not be read from this image.",
            gps_state="NO_GPS_METADATA",
        )

    gps_tags = {k: v for k, v in tags.items() if k.startswith("GPS ")}
    if not gps_tags:
        xmp_result = _extract_xmp_gps(file_bytes, detected_format)
        if xmp_result is not None:
            return xmp_result
        return GPSResult(
            status=MetadataStatus.MISSING,
            note="No GPS coordinates were found in this image.",
            gps_state="NO_GPS_METADATA",
        )

    raw_pairs = tuple(
        (k.removeprefix("GPS "), _format_raw_tag(v))
        for k, v in sorted(gps_tags.items(), key=lambda kv: kv[0])
    )
    extra_pairs = tuple(
        (k.removeprefix("GPS "), _format_raw_tag(v))
        for k, v in sorted(gps_tags.items(), key=lambda kv: kv[0])
        if k not in _COORDINATE_TAG_KEYS
    )

    latitude_tag = gps_tags.get("GPS GPSLatitude")
    longitude_tag = gps_tags.get("GPS GPSLongitude")
    latitude_ref = gps_tags.get("GPS GPSLatitudeRef")
    longitude_ref = gps_tags.get("GPS GPSLongitudeRef")

    if not any(item is not None for item in (latitude_tag, longitude_tag, latitude_ref, longitude_ref)):
        return GPSResult(
            status=MetadataStatus.MISSING,
            note="GPS metadata tags are present, but no GPS coordinates were found in this image.",
            gps_state="GPS_METADATA_PRESENT",
            raw_tags=raw_pairs,
            extra_properties=extra_pairs,
        )

    has_lat_pair = latitude_tag is not None and latitude_ref is not None
    has_lon_pair = longitude_tag is not None and longitude_ref is not None
    if not (has_lat_pair and has_lon_pair):
        return GPSResult(
            status=MetadataStatus.INVALID,
            note="GPS tags are present, but coordinate pairs or hemisphere references are incomplete.",
            gps_state="GPS_COORDINATES_INCOMPLETE",
            raw_tags=raw_pairs,
            extra_properties=extra_pairs,
        )

    latitude_values = getattr(latitude_tag, "values", latitude_tag)
    longitude_values = getattr(longitude_tag, "values", longitude_tag)
    latitude = _coordinate(latitude_values, latitude_ref, latitude=True)
    longitude = _coordinate(longitude_values, longitude_ref, latitude=False)
    if latitude is None or longitude is None:
        return GPSResult(
            status=MetadataStatus.INVALID,
            note="GPS tags are present, but coordinate values are invalid or outside valid ranges.",
            gps_state="GPS_COORDINATES_INVALID",
            raw_tags=raw_pairs,
            extra_properties=extra_pairs,
        )

    altitude = None
    altitude_tag = gps_tags.get("GPS GPSAltitude")
    if altitude_tag is not None:
        altitude_values = getattr(altitude_tag, "values", altitude_tag)
        if not isinstance(altitude_values, (tuple, list)):
            altitude_values = (altitude_values,)
        altitude = _number(altitude_values[0]) if altitude_values else None
        altitude_ref = gps_tags.get("GPS GPSAltitudeRef")
        if altitude is not None and altitude_ref is not None:
            ref_values = getattr(altitude_ref, "values", altitude_ref)
            if not isinstance(ref_values, (tuple, list)):
                ref_values = (ref_values,)
            if ref_values and _number(ref_values[0]) == 1:
                altitude = -altitude

    timestamp = None
    date_tag = gps_tags.get("GPS GPSDate") or gps_tags.get("GPS GPSDateStamp")
    time_tag = gps_tags.get("GPS GPSTimeStamp")
    if date_tag is not None and time_tag is not None:
        date_text = _tag_text(date_tag)
        time_values = getattr(time_tag, "values", time_tag)
        if isinstance(time_values, (list, tuple)):
            time_parts = [_number(item) for item in time_values]
            if date_text and len(time_parts) == 3 and all(item is not None for item in time_parts):
                try:
                    parsed_date = date.fromisoformat(date_text.replace(":", "-", 2))
                    hour, minute, second = (int(float(item)) for item in time_parts if item is not None)
                    if 0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60:
                        timestamp = f"{parsed_date.isoformat()} {hour:02d}:{minute:02d}:{second:02d} UTC"
                except ValueError:
                    timestamp = None

    return GPSResult(
        status=MetadataStatus.PRESENT,
        latitude=latitude,
        longitude=longitude,
        altitude_meters=altitude,
        timestamp_utc=timestamp,
        gps_state="GPS_COORDINATES_AVAILABLE",
        raw_tags=raw_pairs,
        extra_properties=extra_pairs,
    )
