"""Bounds-checked extraction of IPTC-IIM fields from JPEG and TIFF."""

from __future__ import annotations

from io import BytesIO

from PIL import Image

from core.models import MetadataField, MetadataStatus


PHOTOSHOP_HEADER = b"Photoshop 3.0\x00"
SUPPORTED_IPTC_FORMATS = {"JPEG", "TIFF"}
IPTC_FIELD_SPECS: tuple[tuple[str, str, int, int], ...] = (
    ("iptc_headline", "Headline", 2, 105),
    ("iptc_caption", "Caption / description", 2, 120),
    ("iptc_keywords", "Keywords", 2, 25),
    ("iptc_creator", "Creator / byline", 2, 80),
    ("iptc_copyright", "Copyright notice", 2, 116),
    ("iptc_date_created", "Date created", 2, 55),
    ("iptc_city", "City", 2, 90),
    ("iptc_sublocation", "Location description", 2, 92),
    ("iptc_country", "Country", 2, 101),
)


class IPTCReadError(ValueError):
    """An IPTC Photoshop resource or IIM dataset was malformed."""


def _jpeg_iptc_resources(file_bytes: bytes) -> list[bytes]:
    if not file_bytes.startswith(b"\xff\xd8"):
        raise IPTCReadError("JPEG marker stream is malformed.")
    offset = 2
    resources: list[bytes] = []
    while offset < len(file_bytes):
        if file_bytes[offset] != 0xFF:
            raise IPTCReadError("JPEG marker stream is malformed.")
        while offset < len(file_bytes) and file_bytes[offset] == 0xFF:
            offset += 1
        if offset >= len(file_bytes):
            raise IPTCReadError("JPEG marker stream is truncated.")
        marker = file_bytes[offset]
        offset += 1
        if marker in {0xD9, 0xDA}:
            break
        if marker == 0x00 or 0xD0 <= marker <= 0xD8:
            continue
        if offset + 2 > len(file_bytes):
            raise IPTCReadError("JPEG segment length is truncated.")
        segment_length = int.from_bytes(file_bytes[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(file_bytes):
            raise IPTCReadError("JPEG segment length is invalid or truncated.")
        payload = file_bytes[offset + 2 : offset + segment_length]
        if marker == 0xED and payload.startswith(PHOTOSHOP_HEADER):
            resources.extend(_parse_photoshop_resources(payload[len(PHOTOSHOP_HEADER) :]))
        offset += segment_length
    return resources


def _parse_photoshop_resources(data: bytes) -> list[bytes]:
    offset = 0
    iptc: list[bytes] = []
    while offset < len(data):
        if offset + 7 > len(data) or data[offset : offset + 4] != b"8BIM":
            raise IPTCReadError("Photoshop APP13 resource header is malformed.")
        resource_id = int.from_bytes(data[offset + 4 : offset + 6], "big")
        name_length = data[offset + 6]
        name_end = offset + 7 + name_length
        padded_name_end = name_end + ((1 + name_length) & 1)
        if padded_name_end + 4 > len(data):
            raise IPTCReadError("Photoshop APP13 resource name is truncated.")
        size = int.from_bytes(data[padded_name_end : padded_name_end + 4], "big")
        value_start = padded_name_end + 4
        value_end = value_start + size
        padded_end = value_end + (size & 1)
        if padded_end > len(data):
            raise IPTCReadError("Photoshop APP13 resource data is truncated.")
        if resource_id == 0x0404:
            iptc.append(data[value_start:value_end])
        offset = padded_end
    return iptc


def _decode_dataset(value: bytes, utf8: bool) -> str:
    encoding = "utf-8" if utf8 else "latin-1"
    return " ".join(value.decode(encoding, errors="replace").strip("\x00 \t\r\n").split())


def _parse_iim(data: bytes) -> dict[tuple[int, int], list[bytes]]:
    offset = 0
    datasets: dict[tuple[int, int], list[bytes]] = {}
    while offset < len(data):
        if data[offset] != 0x1C:
            if all(byte == 0 for byte in data[offset:]):
                break
            raise IPTCReadError("IPTC-IIM dataset marker is invalid.")
        if offset + 5 > len(data):
            raise IPTCReadError("IPTC-IIM dataset header is truncated.")
        record, dataset = data[offset + 1], data[offset + 2]
        length_word = int.from_bytes(data[offset + 3 : offset + 5], "big")
        offset += 5
        if length_word & 0x8000:
            length_bytes = length_word & 0x7FFF
            if length_bytes == 0 or length_bytes > 4 or offset + length_bytes > len(data):
                raise IPTCReadError("IPTC-IIM extended length is invalid.")
            size = int.from_bytes(data[offset : offset + length_bytes], "big")
            offset += length_bytes
        else:
            size = length_word
        end = offset + size
        if end > len(data):
            raise IPTCReadError("IPTC-IIM dataset length exceeds available data.")
        datasets.setdefault((record, dataset), []).append(data[offset:end])
        offset = end
    if not datasets:
        raise IPTCReadError("IPTC-IIM block contains no datasets.")
    return datasets


def _tiff_iptc(file_bytes: bytes) -> list[bytes]:
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            value = image.tag_v2.get(33723)
            if value is None:
                return []
            if isinstance(value, bytes):
                return [value]
            if isinstance(value, str):
                return [value.encode("latin-1")]
            if isinstance(value, (tuple, list)):
                return [bytes(value)]
            return [bytes(value)]
    except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise IPTCReadError("TIFF metadata could not be read.") from exc


def extract_iptc(file_bytes: bytes, image_format: str) -> tuple[MetadataField, ...]:
    """Return IPTC-IIM values and explicit parse/availability statuses."""
    image_format = image_format.upper()
    if image_format not in SUPPORTED_IPTC_FORMATS:
        status = MetadataStatus.UNSUPPORTED
        note = "IPTC extraction is unsupported for this image format."
        datasets: dict[tuple[int, int], list[bytes]] = {}
        utf8 = False
    else:
        try:
            resources = _jpeg_iptc_resources(file_bytes) if image_format == "JPEG" else _tiff_iptc(file_bytes)
            if not resources:
                status = MetadataStatus.MISSING
                note = None
                datasets = {}
                utf8 = False
            else:
                datasets = {}
                for resource in resources:
                    parsed = _parse_iim(resource)
                    for key, values in parsed.items():
                        datasets.setdefault(key, []).extend(values)
                coded_charset = datasets.get((1, 90), [])
                utf8 = b"\x1b%G" in coded_charset
                status = MetadataStatus.PRESENT
                note = None
        except IPTCReadError as exc:
            status = MetadataStatus.INVALID if any(
                marker in str(exc) for marker in ("invalid", "malformed", "truncated", "exceeds", "no datasets")
            ) else MetadataStatus.UNAVAILABLE
            note = str(exc)
            datasets = {}
            utf8 = False

    fields = [
        MetadataField("iptc", "IPTC-IIM data", "Data parsed" if status is MetadataStatus.PRESENT else None,
                      status, "IPTC", note)
    ]
    for key, label, record, dataset in IPTC_FIELD_SPECS:
        raw_values = datasets.get((record, dataset), [])
        values = [_decode_dataset(value, utf8) for value in raw_values]
        values = [value for value in values if value]
        value = "; ".join(values) if values else None
        field_status = MetadataStatus.PRESENT if value is not None else status
        fields.append(MetadataField(key, label, value, field_status, "IPTC", note if field_status in {MetadataStatus.INVALID, MetadataStatus.UNAVAILABLE} else None))
    return tuple(fields)
