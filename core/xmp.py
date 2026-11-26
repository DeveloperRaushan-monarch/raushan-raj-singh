"""Safe, bounded extraction of common XMP properties from image containers."""

from __future__ import annotations

from io import BytesIO
import xml.etree.ElementTree as ET

from PIL import Image

from core.models import MetadataField, MetadataStatus


XMP_JPEG_HEADER = b"http://ns.adobe.com/xap/1.0/\x00"
XMP_JPEG_EXTENDED_HEADER = b"http://ns.adobe.com/xmp/extension/\x00"
XMP_MAX_BYTES = 1_000_000
XMP_PROPERTIES: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    ("xmp_creator", "Creator (dc:creator)", (("http://purl.org/dc/elements/1.1/", "creator"),)),
    (
        "xmp_creation_date",
        "Creation date (xmp:CreateDate / photoshop:DateCreated)",
        (("http://ns.adobe.com/xap/1.0/", "CreateDate"), ("http://ns.adobe.com/photoshop/1.0/", "DateCreated")),
    ),
    ("xmp_modification_date", "Modification date (xmp:ModifyDate)", (("http://ns.adobe.com/xap/1.0/", "ModifyDate"),)),
    ("xmp_description", "Description (dc:description)", (("http://purl.org/dc/elements/1.1/", "description"),)),
    ("xmp_software", "Creator tool (xmp:CreatorTool)", (("http://ns.adobe.com/xap/1.0/", "CreatorTool"),)),
    ("xmp_rights", "Rights (dc:rights)", (("http://purl.org/dc/elements/1.1/", "rights"),)),
)
SUPPORTED_XMP_FORMATS = {"JPEG", "PNG", "WEBP", "TIFF"}


class XMPReadError(ValueError):
    """An XMP container or XML packet was malformed or exceeded its limit."""


class XMPUnsupportedLocationError(ValueError):
    """XMP was detected in a storage location this parser does not decode."""

    def __init__(self, message: str, partial_packet: bytes | None = None):
        super().__init__(message)
        self.partial_packet = partial_packet


def _jpeg_xmp(file_bytes: bytes) -> bytes | None:
    if not file_bytes.startswith(b"\xff\xd8"):
        raise XMPReadError("JPEG marker stream is malformed.")
    offset = 2
    has_extended_xmp = False
    standard_packet: bytes | None = None
    while offset < len(file_bytes):
        if file_bytes[offset] != 0xFF:
            raise XMPReadError("JPEG marker stream is malformed.")
        while offset < len(file_bytes) and file_bytes[offset] == 0xFF:
            offset += 1
        if offset >= len(file_bytes):
            raise XMPReadError("JPEG marker stream is truncated.")
        marker = file_bytes[offset]
        offset += 1
        if marker in {0xD9, 0xDA}:
            break
        if marker == 0x00 or 0xD0 <= marker <= 0xD8:
            continue
        if offset + 2 > len(file_bytes):
            raise XMPReadError("JPEG segment length is truncated.")
        segment_length = int.from_bytes(file_bytes[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(file_bytes):
            raise XMPReadError("JPEG segment length is invalid or truncated.")
        payload = file_bytes[offset + 2 : offset + segment_length]
        if marker == 0xE1 and payload.startswith(XMP_JPEG_HEADER):
            standard_packet = standard_packet or payload[len(XMP_JPEG_HEADER) :]
        if marker == 0xE1 and payload.startswith(XMP_JPEG_EXTENDED_HEADER):
            has_extended_xmp = True
        offset += segment_length
    if has_extended_xmp:
        raise XMPUnsupportedLocationError(
            "Extended XMP fragments are detected but not reassembled by this parser.",
            partial_packet=standard_packet,
        )
    return standard_packet


def _webp_xmp(file_bytes: bytes) -> bytes | None:
    if len(file_bytes) < 12 or file_bytes[:4] != b"RIFF" or file_bytes[8:12] != b"WEBP":
        raise XMPReadError("WebP RIFF container is malformed.")
    offset = 12
    limit = min(len(file_bytes), int.from_bytes(file_bytes[4:8], "little") + 8)
    while offset < limit:
        if offset + 8 > limit:
            raise XMPReadError("WebP chunk header is truncated.")
        chunk_type = file_bytes[offset : offset + 4]
        chunk_size = int.from_bytes(file_bytes[offset + 4 : offset + 8], "little")
        start, end = offset + 8, offset + 8 + chunk_size
        if end > limit:
            raise XMPReadError("WebP chunk is truncated.")
        if chunk_type == b"XMP ":
            return file_bytes[start:end]
        offset = end + (chunk_size & 1)
    return None


def _image_xmp(file_bytes: bytes, image_format: str) -> bytes | None:
    if image_format == "JPEG":
        return _jpeg_xmp(file_bytes)
    if image_format == "WEBP":
        return _webp_xmp(file_bytes)
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            if image_format == "PNG":
                for key in ("XML:com.adobe.xmp", "xmp"):
                    value = image.info.get(key)
                    if value is not None:
                        return value.encode("utf-8") if isinstance(value, str) else bytes(value)
            if image_format == "TIFF":
                value = image.tag_v2.get(700)
                if value is not None:
                    if isinstance(value, str):
                        return value.encode("utf-8")
                    if isinstance(value, (tuple, list)):
                        return bytes(value).rstrip(b"\x00")
                    return bytes(value).rstrip(b"\x00")
    except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise XMPReadError("Image metadata could not be read.") from exc
    return None


def _xml_values(packet: bytes) -> dict[tuple[str, str], str]:
    if len(packet) > XMP_MAX_BYTES:
        raise XMPReadError("XMP packet exceeds the 1 MB parsing limit.")
    if b"<!DOCTYPE" in packet.upper() or b"<!ENTITY" in packet.upper():
        raise XMPReadError("XMP packets with DTD or entity declarations are not accepted.")
    try:
        root = ET.fromstring(packet)
    except (ET.ParseError, ValueError, UnicodeError) as exc:
        raise XMPReadError("XMP packet contains malformed XML.") from exc

    found: dict[tuple[str, str], list[str]] = {}
    wanted = {prop for _, _, props in XMP_PROPERTIES for prop in props}

    def element_value(element: ET.Element) -> str:
        leaves = [
            " ".join((child.text or "").split())
            for child in element.iter()
            if child is not element and len(child) == 0 and (child.text or "").strip()
        ]
        if leaves:
            return "; ".join(leaves)
        return " ".join(" ".join(element.itertext()).split())

    for element in root.iter():
        if element.tag.startswith("{") and "}" in element.tag:
            namespace, local_name = element.tag[1:].split("}", 1)
            prop = (namespace, local_name)
            if prop in wanted:
                value = element_value(element)
                if value:
                    found.setdefault(prop, []).append(value)
        for attribute, value in element.attrib.items():
            if attribute.startswith("{") and "}" in attribute:
                namespace, local_name = attribute[1:].split("}", 1)
                prop = (namespace, local_name)
                if prop in wanted and value.strip():
                    found.setdefault(prop, []).append(" ".join(value.split()))
    return {key: "; ".join(values) for key, values in found.items()}


def extract_xmp(file_bytes: bytes, image_format: str) -> tuple[MetadataField, ...]:
    """Return XMP packet/property statuses without exposing unrelated metadata."""
    image_format = image_format.upper()
    if image_format not in SUPPORTED_XMP_FORMATS:
        packet_status = MetadataStatus.UNSUPPORTED
        packet_note = "XMP extraction is unsupported for this image format."
        property_status = packet_status
        values: dict[tuple[str, str], str] = {}
    else:
        try:
            packet = _image_xmp(file_bytes, image_format)
            if packet is None:
                packet_status = MetadataStatus.MISSING
                packet_note = None
                property_status = MetadataStatus.MISSING
                values = {}
            else:
                values = _xml_values(packet)
                packet_status = MetadataStatus.PRESENT
                packet_note = None
                property_status = MetadataStatus.MISSING
        except XMPUnsupportedLocationError as exc:
            if exc.partial_packet is None:
                packet_status = MetadataStatus.UNSUPPORTED
                packet_note = str(exc)
                property_status = MetadataStatus.UNSUPPORTED
                values = {}
            else:
                try:
                    values = _xml_values(exc.partial_packet)
                    packet_status = MetadataStatus.PRESENT
                    packet_note = str(exc)
                    property_status = MetadataStatus.MISSING
                except XMPReadError as parse_exc:
                    packet_status = MetadataStatus.INVALID
                    packet_note = str(parse_exc)
                    property_status = MetadataStatus.UNAVAILABLE
                    values = {}
        except XMPReadError as exc:
            packet_status = MetadataStatus.INVALID if "malformed" in str(exc) or "DTD" in str(exc) or "entity" in str(exc) else MetadataStatus.UNAVAILABLE
            packet_note = str(exc)
            property_status = MetadataStatus.UNAVAILABLE
            values = {}

    fields = [
        MetadataField("xmp", "XMP packet", "Packet parsed" if packet_status is MetadataStatus.PRESENT else None,
                      packet_status, "XMP", packet_note)
    ]
    for key, label, properties in XMP_PROPERTIES:
        value = next((values[prop] for prop in properties if prop in values), None)
        status = MetadataStatus.PRESENT if value is not None else property_status
        fields.append(MetadataField(key, label, value, status, "XMP", packet_note if status is MetadataStatus.UNAVAILABLE else None))
    return tuple(fields)
