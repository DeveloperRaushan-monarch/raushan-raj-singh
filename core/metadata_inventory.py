"""Comprehensive, bounded, non-GPS metadata inventory extraction (Phase 6C)."""

from __future__ import annotations

from io import BytesIO
from pathlib import PurePosixPath
import struct
import time
from typing import Any
import xml.etree.ElementTree as ET

import exifread
from PIL import ExifTags, Image, ImageCms

from core.exiftool_engine import run_exiftool
from core.format_capabilities import get_format_capability, identify_file_signature
from core.metadata_merger import merge_metadata_records

from core.iptc import (
    IPTC_FIELD_SPECS,
    SUPPORTED_IPTC_FORMATS,
    IPTCReadError,
    _decode_dataset,
    _jpeg_iptc_resources,
    _parse_iim,
    _tiff_iptc,
)
from core.metadata import EXIF_CAPABLE_FORMATS
from core.metadata_models import (
    MetadataExtractionCoverage,
    MetadataExtractionStage,
    MetadataExtractionWarning,
    MetadataInventory,
    MetadataRecord,
    StageCompletionState,
)
from core.models import ImageProperties, MetadataStatus
from core.xmp import (
    SUPPORTED_XMP_FORMATS,
    XMP_MAX_BYTES,
    XMPReadError,
    XMPUnsupportedLocationError,
    _image_xmp,
)


MAX_METADATA_RECORDS = 2000
MAX_XMP_DEPTH = 16
MAX_XMP_NODES = 1000
MAX_ICC_BYTES = 4_000_000
MAX_BINARY_HEX_BYTES = 64

GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "Parser completion indicates bounded extraction finished; proprietary, encrypted, "
    "stripped, or unrecognized metadata may not be recoverable.",
)

_EXIF_CATEGORY_MAP: dict[str, str] = {
    "Make": "Camera Information",
    "Model": "Camera Information",
    "BodySerialNumber": "Camera Information",
    "CameraOwnerName": "Camera Information",
    "LensMake": "Lens Information",
    "LensModel": "Lens Information",
    "LensSpecification": "Lens Information",
    "LensSerialNumber": "Lens Information",
    "FocalLengthIn35mmFilm": "Lens Information",
    "MaxApertureValue": "Lens Information",
    "DateTimeOriginal": "Capture Information",
    "DateTimeDigitized": "Capture Information",
    "DateTime": "Capture Information",
    "OffsetTime": "Capture Information",
    "OffsetTimeOriginal": "Capture Information",
    "OffsetTimeDigitized": "Capture Information",
    "SubSecTime": "Capture Information",
    "SubSecTimeOriginal": "Capture Information",
    "SubSecTimeDigitized": "Capture Information",
    "ExposureTime": "Exposure Information",
    "FNumber": "Exposure Information",
    "ISOSpeedRatings": "Exposure Information",
    "PhotographicSensitivity": "Exposure Information",
    "FocalLength": "Exposure Information",
    "Flash": "Exposure Information",
    "WhiteBalance": "Exposure Information",
    "MeteringMode": "Exposure Information",
    "ExposureProgram": "Exposure Information",
    "ExposureBiasValue": "Exposure Information",
    "ShutterSpeedValue": "Exposure Information",
    "ApertureValue": "Exposure Information",
    "LightSource": "Exposure Information",
    "SceneCaptureType": "Exposure Information",
    "ExposureMode": "Exposure Information",
    "ExifImageWidth": "Image Information",
    "ExifImageLength": "Image Information",
    "PixelXDimension": "Image Information",
    "PixelYDimension": "Image Information",
    "Orientation": "Image Information",
    "ColorSpace": "Image Information",
    "XResolution": "Image Information",
    "YResolution": "Image Information",
    "ResolutionUnit": "Image Information",
    "Compression": "Image Information",
    "BitsPerSample": "Image Information",
    "SamplesPerPixel": "Image Information",
    "PhotometricInterpretation": "Image Information",
    "Software": "Software Information",
    "ProcessingSoftware": "Software Information",
}

_KNOWN_XMP_NAMESPACES: set[str] = {
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "adobe:ns:meta/",
    "http://purl.org/dc/elements/1.1/",
    "http://ns.adobe.com/xap/1.0/",
    "http://ns.adobe.com/xap/1.0/mm/",
    "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "http://ns.adobe.com/photoshop/1.0/",
    "http://ns.adobe.com/exif/1.0/",
    "http://ns.adobe.com/tiff/1.0/",
    "http://ns.adobe.com/exif/1.0/aux/",
}

_IPTC_DATASET_NAMES: dict[tuple[int, int], str] = {
    **{(rec, ds): label for _, label, rec, ds in IPTC_FIELD_SPECS},
    (1, 90): "Coded character set",
    (2, 0): "Record version",
    (2, 5): "Object name / title",
    (2, 15): "Category",
    (2, 20): "Supplemental categories",
    (2, 40): "Special instructions",
    (2, 60): "Time created",
    (2, 85): "By-line title",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 118): "Contact",
}


def _truncate_bytes(data: bytes) -> tuple[dict[str, Any], str, str]:
    summary = {
        "byte_length": len(data),
        "hex_prefix": data[:MAX_BINARY_HEX_BYTES].hex(),
    }
    note = (
        f"Binary value truncated to {MAX_BINARY_HEX_BYTES}-byte hex prefix for safe display."
        if len(data) > MAX_BINARY_HEX_BYTES
        else "Raw binary bytes represented as hex."
    )
    return summary, f"<{len(data)} bytes: {summary['hex_prefix'][:32]}>", note


def _is_rational(value: object) -> tuple[int, int] | None:
    if hasattr(value, "num") and hasattr(value, "den"):
        try:
            return int(getattr(value, "num")), int(getattr(value, "den"))
        except (TypeError, ValueError):
            return None
    if hasattr(value, "numerator") and hasattr(value, "denominator") and not isinstance(value, (int, bool)):
        try:
            return int(getattr(value, "numerator")), int(getattr(value, "denominator"))
        except (TypeError, ValueError):
            return None
    return None


def _normalize_value(value: object, printable: str | None = None) -> tuple[Any, str, str, str | None]:
    """Return (raw_value, interpreted_value, data_type, limitations) preserving rationals."""
    ratio = _is_rational(value)
    if ratio is not None:
        num, den = ratio
        raw = {"numerator": num, "denominator": den}
        if den == 0:
            interp = f"{num}/0 (undefined)"
        elif den == 1:
            interp = str(num)
        else:
            interp = f"{num}/{den} ({num / den:.6g})"
        return raw, interp, "rational", None

    if isinstance(value, (bytes, bytearray)):
        raw_b, interp_b, note_b = _truncate_bytes(bytes(value))
        return raw_b, interp_b, "bytes", note_b

    if isinstance(value, bool):
        return value, str(value), "boolean", None

    if isinstance(value, int):
        return value, printable if printable is not None else str(value), "integer", None

    if isinstance(value, float):
        return value, printable if printable is not None else str(value), "float", None

    if isinstance(value, (list, tuple)):
        if len(value) == 1 and isinstance(value[0], int) and not isinstance(value[0], bool):
            return value[0], printable if printable is not None else str(value[0]), "integer", None
        if len(value) == 1 and _is_rational(value[0]) is not None:
            return _normalize_value(value[0], printable=printable)
        ratios = [_is_rational(item) for item in value]
        if value and all(r is not None for r in ratios):
            raw_list = [{"numerator": r[0], "denominator": r[1]} for r in ratios if r is not None]
            interp = printable or ", ".join(f"{r['numerator']}/{r['denominator']}" for r in raw_list)
            return raw_list, interp, "array", None
        if len(value) > MAX_BINARY_HEX_BYTES and all(isinstance(x, int) for x in value):
            raw_b, interp_b, note_b = _truncate_bytes(bytes(x & 0xFF for x in value[:MAX_BINARY_HEX_BYTES]))
            raw_b["byte_length"] = len(value)
            return raw_b, f"<{len(value)} byte values>", "bytes", note_b
        safe_items = [str(item) if _is_rational(item) is None else f"{_is_rational(item)[0]}/{_is_rational(item)[1]}" for item in value[:64]]
        note = "Array truncated to 64 items." if len(value) > 64 else None
        return safe_items, printable or ", ".join(safe_items), "array", note

    text = " ".join(str(value).strip().split())
    return text, printable if printable is not None else text, "string", None


_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "JPEG": "JPEG (Joint Photographic Experts Group)",
    "PNG": "PNG (Portable Network Graphics)",
    "WEBP": "WebP (Google WebP Image)",
    "TIFF": "TIFF (Tagged Image File Format)",
    "GIF": "GIF (Graphics Interchange Format)",
    "BMP": "BMP (Windows Bitmap)",
}

_SIGNATURE_DESCRIPTIONS: dict[str, str] = {
    "JPEG": "JPEG SOI marker (FF D8 FF)",
    "PNG": "PNG signature (89 50 4E 47 0D 0A 1A 0A)",
    "WEBP": "RIFF/WEBP container header",
    "TIFF": "TIFF byte-order header (II* / MM*)",
    "GIF": "GIF87a / GIF89a header",
    "BMP": "BMP 'BM' header (42 4D)",
}


def _format_size_human(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes:,} bytes ({size_bytes / (1024 * 1024):.2f} MB)"
    return f"{size_bytes:,} bytes ({size_bytes / 1024:.2f} KB)"


def _extract_container(
    file_bytes: bytes, properties: ImageProperties
) -> tuple[list[MetadataRecord], MetadataExtractionStage]:
    records: list[MetadataRecord] = []
    warnings: list[MetadataExtractionWarning] = []
    magic = file_bytes[:16].hex(" ").upper()
    fmt_upper = properties.image_format.upper()

    file_ext = PurePosixPath((properties.filename or "").replace("\\", "/")).suffix.lstrip(".").lower() or "None"
    header_preview_bytes = file_bytes[:32]
    header_preview_hex = header_preview_bytes.hex(" ").upper()

    file_items: list[tuple[str, str, str, Any, str, str]] = [
        (
            "FileSignature",
            "File signature (magic bytes)",
            "File Inspector",
            magic,
            f"{_SIGNATURE_DESCRIPTIONS.get(fmt_upper, 'Binary file header')} — {magic}",
            "string",
        ),
        (
            "RawHeaderPreview",
            "Raw header preview",
            "File Inspector",
            header_preview_hex,
            f"First {len(header_preview_bytes)} bytes (hex): {header_preview_hex}",
            "string",
        ),
        (
            "DetectedFormat",
            "Detected format",
            "Image Decoder",
            properties.image_format,
            _FORMAT_DESCRIPTIONS.get(fmt_upper, properties.image_format),
            "string",
        ),
        (
            "FileExtension",
            "File extension",
            "File Inspector",
            file_ext,
            file_ext,
            "string",
        ),
        (
            "MimeType",
            "MIME type",
            "File Inspector",
            properties.mime_type,
            properties.mime_type,
            "string",
        ),
        (
            "FileSizeBytes",
            "File size (bytes)",
            "File Inspector",
            properties.file_size_bytes,
            _format_size_human(properties.file_size_bytes),
            "integer",
        ),
        (
            "ExtensionMismatch",
            "Extension mismatch",
            "File Inspector",
            properties.extension_mismatch,
            (
                "Yes (filename extension does not match detected format)"
                if properties.extension_mismatch
                else "No (extension matches detected format)"
            ),
            "boolean",
        ),
    ]
    for name, label, src, raw_val, interp_val, dtype in file_items:
        records.append(
            MetadataRecord(
                record_id=f"container:file:{name}",
                source=src,
                category="File Information",
                tag_name=label,
                namespace="File",
                path=("File", name),
                raw_value=raw_val,
                interpreted_value=interp_val,
                data_type=dtype,
                status=MetadataStatus.PRESENT,
            )
        )

    channel_count: int | None = None
    try:
        with Image.open(BytesIO(file_bytes)) as probe:
            channel_count = len(probe.getbands())
    except (OSError, ValueError, TypeError):
        channel_count = None

    img_items: list[tuple[str, str, Any, str, str]] = [
        ("Dimensions", "Image dimensions", f"{properties.width} × {properties.height}", f"{properties.width} × {properties.height} px", "string"),
        ("Width", "Image width (px)", properties.width, f"{properties.width} px", "integer"),
        ("Height", "Image height (px)", properties.height, f"{properties.height} px", "integer"),
        ("Megapixels", "Megapixels", round(properties.megapixels, 4), f"{properties.megapixels:.2f} MP", "float"),
        ("AspectRatio", "Aspect ratio", round(properties.aspect_ratio, 4), f"{properties.aspect_ratio:.3f}:1", "float"),
        ("ColorMode", "Colour mode", properties.color_mode, properties.color_mode, "string"),
        ("FrameCount", "Frame count", properties.frame_count, f"{properties.frame_count} frame(s)", "integer"),
        ("HasTransparency", "Transparency", properties.has_transparency, "Yes" if properties.has_transparency else "No", "boolean"),
    ]
    if channel_count is not None:
        img_items.insert(5, ("ColourChannels", "Colour channels", channel_count, f"{channel_count} channel(s)", "integer"))
    if properties.bit_depth_per_channel is not None:
        img_items.append(
            ("BitDepth", "Bit depth per channel", properties.bit_depth_per_channel, f"{properties.bit_depth_per_channel} bits per channel", "integer")
        )
    elif fmt_upper == "PNG" and len(file_bytes) >= 26 and file_bytes[:8] == b"\x89PNG\r\n\x1a\n" and file_bytes[12:16] == b"IHDR":
        ihdr_depth = file_bytes[24]
        if ihdr_depth in {1, 2, 4, 8, 16}:
            img_items.append(
                ("BitDepth", "Bit depth per channel", ihdr_depth, f"{ihdr_depth} bits per channel (PNG IHDR)", "integer")
            )

    for name, label, val, interp_val, dtype in img_items:
        records.append(
            MetadataRecord(
                record_id=f"container:image:{name}",
                source="Image Decoder",
                category="Image Information",
                tag_name=label,
                namespace="Container",
                path=("Container", name),
                raw_value=val,
                interpreted_value=interp_val,
                data_type=dtype,
                status=MetadataStatus.PRESENT,
            )
        )

    try:
        with Image.open(BytesIO(file_bytes)) as img:
            for key, val in sorted(img.info.items(), key=lambda kv: str(kv[0])):
                key_str = str(key)
                if key_str in {"exif", "icc_profile", "XML:com.adobe.xmp", "xmp", "photoshop"}:
                    continue
                if key_str.lower().startswith("raw profile type"):
                    continue
                raw_v, interp_v, dtype_v, note_v = _normalize_value(val)
                lower_key = key_str.lower()
                if lower_key == "dpi" and isinstance(val, (tuple, list)) and len(val) == 2:
                    try:
                        dx, dy = float(val[0]), float(val[1])
                        interp_v = f"{dx:g} × {dy:g} DPI"
                    except (TypeError, ValueError):
                        pass
                if fmt_upper == "JPEG" and (lower_key.startswith("jfif") or lower_key in {"progressive", "progression", "adobe", "adobe_transform"}):
                    src_k = "JPEG Container"
                    cat_k = "JPEG Structure"
                    ns_k = "JPEG"
                    sub_ns = "JFIF" if lower_key.startswith("jfif") else "Structure"
                    path_k = ("JPEG", sub_ns, key_str)
                elif fmt_upper == "PNG":
                    src_k = "PNG Chunk"
                    cat_k = "Software Information" if lower_key == "software" else "PNG Structure"
                    ns_k = "PNG"
                    path_k = ("PNG", "Info", key_str)
                elif fmt_upper == "WEBP":
                    src_k = "WebP RIFF Chunk"
                    cat_k = "WebP Structure"
                    ns_k = "WebP"
                    path_k = ("WebP", "Info", key_str)
                else:
                    src_k = "Image Decoder"
                    cat_k = "Software Information" if lower_key == "software" else "Image Information"
                    ns_k = "ContainerInfo"
                    path_k = ("ContainerInfo", key_str)
                records.append(
                    MetadataRecord(
                        record_id=f"container:info:{key_str}",
                        source=src_k,
                        category=cat_k,
                        tag_name=key_str,
                        namespace=ns_k,
                        path=path_k,
                        raw_value=raw_v,
                        interpreted_value=interp_v,
                        data_type=dtype_v,
                        status=MetadataStatus.PRESENT,
                        limitations=note_v,
                    )
                )
    except (OSError, ValueError, TypeError) as exc:
        warnings.append(MetadataExtractionWarning("container", "CONTAINER_INFO_PARTIAL", str(exc)))

    # Format-specific structural chunk inspection (bounded, read-only)
    fmt = properties.image_format.upper()
    if fmt == "PNG" and file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        png_chunks: list[str] = []
        while pos + 8 <= len(file_bytes) and len(png_chunks) < 64:
            chunk_len = struct.unpack(">I", file_bytes[pos : pos + 4])[0]
            chunk_type = file_bytes[pos + 4 : pos + 8].decode("ascii", errors="replace")
            png_chunks.append(f"{chunk_type} ({chunk_len}B)")
            if chunk_type == "IEND" or pos + 12 + chunk_len > len(file_bytes):
                break
            pos += 12 + chunk_len
        if png_chunks:
            records.append(
                MetadataRecord(
                    record_id="container:png:chunks",
                    source="PNG Chunk",
                    category="PNG Structure",
                    tag_name="PNG chunks",
                    namespace="PNG",
                    path=("PNG", "Chunks"),
                    raw_value=png_chunks,
                    interpreted_value=", ".join(png_chunks),
                    data_type="array",
                    status=MetadataStatus.PRESENT,
                )
            )
    elif fmt == "WEBP" and len(file_bytes) >= 12 and file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        pos = 12
        webp_chunks: list[str] = []
        while pos + 8 <= len(file_bytes) and len(webp_chunks) < 64:
            chunk_id = file_bytes[pos : pos + 4].decode("ascii", errors="replace")
            chunk_len = struct.unpack("<I", file_bytes[pos + 4 : pos + 8])[0]
            webp_chunks.append(f"{chunk_id.strip()} ({chunk_len}B)")
            padded = chunk_len + (chunk_len % 2)
            if pos + 8 + padded > len(file_bytes):
                break
            pos += 8 + padded
        if webp_chunks:
            records.append(
                MetadataRecord(
                    record_id="container:webp:chunks",
                    source="WebP RIFF Chunk",
                    category="WebP Structure",
                    tag_name="WebP RIFF chunks",
                    namespace="WebP",
                    path=("WebP", "RIFFChunks"),
                    raw_value=webp_chunks,
                    interpreted_value=", ".join(webp_chunks),
                    data_type="array",
                    status=MetadataStatus.PRESENT,
                    source_engine="WebP Parser",
                    source_container="RIFF/WebP",
                )
            )
    elif fmt == "GIF" and file_bytes.startswith((b"GIF87a", b"GIF89a")) and len(file_bytes) >= 13:
        gif_ver = file_bytes[:6].decode("ascii")
        lsd_w, lsd_h, packed, bg_idx, px_aspect = struct.unpack("<HHBBB", file_bytes[6:13])
        gct_flag = bool(packed & 0x80)
        gct_size = 2 ** ((packed & 0x07) + 1) if gct_flag else 0
        for g_key, g_label, g_raw, g_interp, g_dtype in (
            ("Header", "GIF header version", gif_ver, gif_ver, "string"),
            ("LogicalScreen", "Logical screen dimensions", f"{lsd_w} × {lsd_h}", f"{lsd_w} × {lsd_h} px", "string"),
            ("GlobalColorTable", "Global colour table", gct_size, f"Present ({gct_size} colours)" if gct_flag else "Absent", "integer"),
            ("BackgroundColorIndex", "Background colour index", bg_idx, str(bg_idx), "integer"),
        ):
            records.append(
                MetadataRecord(
                    record_id=f"container:gif:{g_key}",
                    source="GIF Container",
                    category="GIF / Animation",
                    tag_name=g_label,
                    namespace="GIF",
                    path=("GIF", g_key),
                    raw_value=g_raw,
                    interpreted_value=g_interp,
                    data_type=g_dtype,
                    status=MetadataStatus.PRESENT,
                    source_engine="GIF Parser",
                    source_container="GIF Header",
                )
            )
    elif fmt == "BMP" and file_bytes.startswith(b"BM") and len(file_bytes) >= 34:
        bmp_file_size, _, _, data_offset, dib_size = struct.unpack("<IHHIi", file_bytes[2:18])
        comp_code = struct.unpack("<I", file_bytes[30:34])[0] if dib_size >= 40 and len(file_bytes) >= 34 else None
        comp_names = {0: "BI_RGB (Uncompressed)", 1: "BI_RLE8", 2: "BI_RLE4", 3: "BI_BITFIELDS"}
        for b_key, b_label, b_raw, b_interp, b_dtype in (
            ("DIBHeaderSize", "DIB header size", dib_size, f"{dib_size} bytes", "integer"),
            ("PixelDataOffset", "Pixel data offset", data_offset, f"Byte {data_offset}", "integer"),
        ):
            records.append(
                MetadataRecord(
                    record_id=f"container:bmp:{b_key}",
                    source="BMP Container",
                    category="Other Container Metadata",
                    tag_name=b_label,
                    namespace="BMP",
                    path=("BMP", b_key),
                    raw_value=b_raw,
                    interpreted_value=b_interp,
                    data_type=b_dtype,
                    status=MetadataStatus.PRESENT,
                    source_engine="BMP Parser",
                    source_container="BMP Header",
                )
            )
        if comp_code is not None:
            records.append(
                MetadataRecord(
                    record_id="container:bmp:Compression",
                    source="BMP Container",
                    category="Other Container Metadata",
                    tag_name="BMP compression",
                    namespace="BMP",
                    path=("BMP", "Compression"),
                    raw_value=comp_code,
                    interpreted_value=comp_names.get(comp_code, f"Code {comp_code}"),
                    data_type="integer",
                    status=MetadataStatus.PRESENT,
                    source_engine="BMP Parser",
                    source_container="BMP DIB",
                )
            )
    elif fmt == "TIFF" and file_bytes.startswith((b"II*\x00", b"MM\x00*")):
        byte_order = "Little-endian (Intel II)" if file_bytes.startswith(b"II*\x00") else "Big-endian (Motorola MM)"
        records.append(
            MetadataRecord(
                record_id="container:tiff:ByteOrder",
                source="TIFF Container",
                category="TIFF Structure",
                tag_name="TIFF byte order",
                namespace="TIFF",
                path=("TIFF", "ByteOrder"),
                raw_value=file_bytes[:2].decode("ascii"),
                interpreted_value=byte_order,
                data_type="string",
                status=MetadataStatus.PRESENT,
                source_engine="TIFF Parser",
                source_container="TIFF Header",
            )
        )
    elif fmt == "JPEG" and file_bytes.startswith(b"\xff\xd8"):
        pos = 2
        jpeg_segments: list[str] = []
        sof_parsed = False
        app0_parsed = False
        _SOF_PROCESSES: dict[int, tuple[str, bool]] = {
            0xC0: ("Baseline DCT, Huffman coding", False),
            0xC1: ("Extended sequential DCT, Huffman coding", False),
            0xC2: ("Progressive DCT, Huffman coding", True),
            0xC3: ("Lossless (sequential), Huffman coding", False),
            0xC5: ("Differential sequential DCT, Huffman coding", False),
            0xC6: ("Differential progressive DCT, Huffman coding", True),
            0xC7: ("Differential lossless, Huffman coding", False),
            0xC9: ("Extended sequential DCT, arithmetic coding", False),
            0xCA: ("Progressive DCT, arithmetic coding", True),
            0xCB: ("Lossless (sequential), arithmetic coding", False),
        }
        while pos + 2 <= len(file_bytes) and len(jpeg_segments) < 64:
            if file_bytes[pos] != 0xFF:
                warnings.append(
                    MetadataExtractionWarning(
                        "container",
                        "JPEG_SEGMENT_INVALID",
                        "Unexpected byte before JPEG marker; segment stream may be malformed or truncated.",
                    )
                )
                break
            while pos < len(file_bytes) and file_bytes[pos] == 0xFF:
                pos += 1
            if pos >= len(file_bytes):
                warnings.append(
                    MetadataExtractionWarning("container", "JPEG_TRUNCATED", "JPEG marker stream ended unexpectedly.")
                )
                break
            marker = file_bytes[pos]
            pos += 1
            if marker == 0xD9 or marker == 0xDA:  # EOI or SOS
                jpeg_segments.append("SOS" if marker == 0xDA else "EOI")
                break
            if marker == 0x00 or (0xD0 <= marker <= 0xD7) or marker == 0x01:
                continue
            if pos + 2 > len(file_bytes):
                warnings.append(
                    MetadataExtractionWarning("container", "JPEG_TRUNCATED", "JPEG segment length header is truncated.")
                )
                break
            seg_len = struct.unpack(">H", file_bytes[pos : pos + 2])[0]
            if seg_len < 2 or pos + seg_len > len(file_bytes):
                warnings.append(
                    MetadataExtractionWarning("container", "JPEG_SEGMENT_INVALID", "JPEG segment length is invalid or truncated.")
                )
                break
            payload = file_bytes[pos + 2 : pos + seg_len]

            if 0xE0 <= marker <= 0xEF:
                label = f"APP{marker - 0xE0}"
            elif marker == 0xFE:
                label = "COM"
            elif marker in _SOF_PROCESSES:
                label = f"SOF{marker - 0xC0}"
            else:
                label = f"0xFF{marker:02X}"
            jpeg_segments.append(f"{label} ({len(payload)}B)")

            # Parse APP0 JFIF header
            if marker == 0xE0 and not app0_parsed and payload.startswith(b"JFIF\x00"):
                app0_parsed = True
                if len(payload) < 14:
                    warnings.append(
                        MetadataExtractionWarning("container", "JPEG_APP0_MALFORMED", "JPEG APP0 JFIF payload is truncated.")
                    )
                else:
                    ver_maj, ver_min, unit, x_den, y_den, tw, th = struct.unpack(">BBBHHBB", payload[5:14])
                    ver_str = f"{ver_maj}.{ver_min:02d}"
                    unit_desc = {
                        0: "None (aspect ratio only)",
                        1: "Pixels per inch (DPI)",
                        2: "Pixels per centimetre",
                    }.get(unit, f"Unknown ({unit})")
                    x_desc = f"{x_den} DPI" if unit == 1 else (f"{x_den} px/cm" if unit == 2 else f"{x_den} (aspect ratio)")
                    y_desc = f"{y_den} DPI" if unit == 1 else (f"{y_den} px/cm" if unit == 2 else f"{y_den} (aspect ratio)")
                    jfif_items = [
                        ("JFIFVersion", "JFIF version", ver_str, ver_str, "string"),
                        ("ResolutionUnit", "Resolution unit", unit, unit_desc, "integer"),
                        ("XResolution", "X resolution", x_den, x_desc, "integer"),
                        ("YResolution", "Y resolution", y_den, y_desc, "integer"),
                    ]
                    if tw > 0 or th > 0:
                        jfif_items.append(("ThumbnailSize", "JFIF thumbnail dimensions", f"{tw} × {th}", f"{tw} × {th} px", "string"))
                    for j_name, j_label, j_raw, j_interp, j_dtype in jfif_items:
                        records.append(
                            MetadataRecord(
                                record_id=f"container:jpeg:jfif:{j_name}",
                                source="JPEG Container",
                                category="JPEG / JFIF Information",
                                tag_name=j_label,
                                namespace="JPEG",
                                path=("JPEG Container", "APP0", j_name),
                                raw_value=j_raw,
                                interpreted_value=j_interp,
                                data_type=j_dtype,
                                status=MetadataStatus.PRESENT,
                            )
                        )

            # Parse SOF frame header
            if marker in _SOF_PROCESSES and not sof_parsed:
                sof_parsed = True
                enc_desc, is_prog = _SOF_PROCESSES[marker]
                if len(payload) < 6:
                    warnings.append(
                        MetadataExtractionWarning("container", "JPEG_SOF_MALFORMED", "JPEG SOF frame header is truncated.")
                    )
                else:
                    precision, sof_h, sof_w, num_comp = struct.unpack(">BHHB", payload[:6])
                    if sof_h <= 0 or sof_w <= 0 or num_comp <= 0 or len(payload) < 6 + 3 * num_comp:
                        warnings.append(
                            MetadataExtractionWarning("container", "JPEG_SOF_MALFORMED", "JPEG SOF frame dimensions or component table are invalid.")
                        )
                    else:
                        if (sof_w, sof_h) != (properties.width, properties.height):
                            warnings.append(
                                MetadataExtractionWarning(
                                    "container",
                                    "JPEG_SOF_DIMENSION_MISMATCH",
                                    f"JPEG SOF dimensions ({sof_w}×{sof_h}) differ from decoded dimensions ({properties.width}×{properties.height}).",
                                )
                            )
                        sampling_pairs: list[tuple[int, int]] = []
                        comp_ids: list[int] = []
                        for c_idx in range(num_comp):
                            cid, hv, _qt = struct.unpack(">BBB", payload[6 + 3 * c_idx : 9 + 3 * c_idx])
                            comp_ids.append(cid)
                            sampling_pairs.append(((hv >> 4) & 0x0F, hv & 0x0F))

                        sof_items: list[tuple[str, str, Any, str, str]] = [
                            ("EncodingProcess", "Encoding process", f"SOF{marker - 0xC0} (0xFF{marker:02X})", enc_desc, "string"),
                            ("Progressive", "Progressive encoding", is_prog, "Yes" if is_prog else "No (Baseline/Sequential)", "boolean"),
                            ("Precision", "Bits per sample", precision, f"{precision} bits per sample", "integer"),
                            ("ColorComponents", "Colour components", num_comp, f"{num_comp} component(s)", "integer"),
                            ("SOFDimensions", "SOF frame dimensions", f"{sof_w} × {sof_h}", f"{sof_w} × {sof_h} px", "string"),
                        ]
                        if num_comp == 3 and len(sampling_pairs) == 3:
                            (h1, v1), (h2, v2), (h3, v3) = sampling_pairs
                            if h2 == 1 and v2 == 1 and h3 == 1 and v3 == 1:
                                sub_map = {
                                    (2, 2): "YCbCr 4:2:0 (2 2)",
                                    (2, 1): "YCbCr 4:2:2 (2 1)",
                                    (1, 2): "YCbCr 4:4:0 (1 2)",
                                    (1, 1): "YCbCr 4:4:4 (1 1)",
                                }
                                sub_interp = sub_map.get((h1, v1), f"Sampling ({h1}x{v1}, {h2}x{v2}, {h3}x{v3})")
                            else:
                                sub_interp = f"Sampling ({h1}x{v1}, {h2}x{v2}, {h3}x{v3})"
                            sof_items.append(
                                (
                                    "ComponentSampling",
                                    "YCbCr subsampling",
                                    [f"{h}x{v}" for h, v in sampling_pairs],
                                    sub_interp,
                                    "array",
                                )
                            )
                        for s_name, s_label, s_raw, s_interp, s_dtype in sof_items:
                            records.append(
                                MetadataRecord(
                                    record_id=f"container:jpeg:sof:{s_name}",
                                    source="JPEG Container",
                                    category="JPEG / JFIF Information",
                                    tag_name=s_label,
                                    namespace="JPEG",
                                    path=("JPEG Container", "SOF", s_name),
                                    raw_value=s_raw,
                                    interpreted_value=s_interp,
                                    data_type=s_dtype,
                                    status=MetadataStatus.PRESENT,
                                )
                            )

            pos += seg_len
        if jpeg_segments:
            records.append(
                MetadataRecord(
                    record_id="container:jpeg:segments",
                    source="JPEG Container",
                    category="JPEG Structure",
                    tag_name="JPEG marker segments",
                    namespace="JPEG",
                    path=("JPEG", "Segments"),
                    raw_value=jpeg_segments,
                    interpreted_value=", ".join(jpeg_segments),
                    data_type="array",
                    status=MetadataStatus.PRESENT,
                )
            )

    state = StageCompletionState.PARTIAL if warnings else StageCompletionState.COMPLETED
    return records, MetadataExtractionStage(
        stage_id="container",
        source_standard="Container",
        completion_state=state,
        records_extracted=len(records),
        warnings=tuple(warnings),
        limitations=("Container metadata reflects decoded header properties and safe info chunks.",),
    )


def _extract_exif_makernotes_thumbnail(
    file_bytes: bytes, image_format: str
) -> tuple[
    list[MetadataRecord],
    MetadataExtractionStage,
    MetadataExtractionStage,
    MetadataExtractionStage,
    bool,
]:
    if image_format.upper() not in EXIF_CAPABLE_FORMATS:
        msg = f"EXIF extraction is unsupported for {image_format}."
        return (
            [],
            MetadataExtractionStage("exif", "EXIF", StageCompletionState.UNSUPPORTED, 0, unsupported_features=(msg,), limitations=(msg,)),
            MetadataExtractionStage("makernotes", "EXIF MakerNotes", StageCompletionState.UNSUPPORTED, 0, unsupported_features=(msg,), limitations=(msg,)),
            MetadataExtractionStage("thumbnail", "Thumbnail", StageCompletionState.UNSUPPORTED, 0, unsupported_features=(msg,), limitations=(msg,)),
            False,
        )

    exif_records: list[MetadataRecord] = []
    mn_records: list[MetadataRecord] = []
    thumb_records: list[MetadataRecord] = []
    exif_warnings: list[MetadataExtractionWarning] = []
    mn_warnings: list[MetadataExtractionWarning] = []
    thumb_warnings: list[MetadataExtractionWarning] = []
    gps_present = False
    seen_exif_tags: set[str] = set()
    raw_makernote_blob: bytes | None = None

    if image_format.upper() in {"JPEG", "TIFF"}:
        try:
            tags = exifread.process_file(BytesIO(file_bytes), details=True, strict=False)
            for full_key, tag_obj in sorted(tags.items(), key=lambda kv: str(kv[0])):
                key_str = str(full_key)
                if key_str.startswith("GPS "):
                    gps_present = True
                    continue

                if key_str in {"JPEGThumbnail", "TIFFThumbnail"} and isinstance(tag_obj, (bytes, bytearray)):
                    thumb_records.append(
                        MetadataRecord(
                            record_id=f"thumbnail:{key_str}",
                            source="Thumbnail",
                            category="Thumbnail Information",
                            tag_name=key_str,
                            namespace="Thumbnail",
                            path=("Thumbnail", key_str),
                            raw_value={"byte_length": len(tag_obj)},
                            interpreted_value=f"Embedded {key_str.replace('Thumbnail', '')} thumbnail ({len(tag_obj)} bytes)",
                            data_type="bytes",
                            status=MetadataStatus.PRESENT,
                            limitations="Raw thumbnail bytes are not embedded in metadata inventory.",
                        )
                    )
                    continue

                if key_str.startswith("Thumbnail "):
                    short_name = key_str[len("Thumbnail ") :]
                    raw_v, interp_v, dtype_v, note_v = _normalize_value(
                        getattr(tag_obj, "values", tag_obj),
                        getattr(tag_obj, "printable", None),
                    )
                    tag_id_hex = f"0x{tag_obj.tag:04X}" if hasattr(tag_obj, "tag") else None
                    thumb_records.append(
                        MetadataRecord(
                            record_id=f"thumbnail:{short_name}",
                            source="Thumbnail",
                            category="Thumbnail Information",
                            tag_name=short_name,
                            tag_id=tag_id_hex,
                            namespace="Thumbnail",
                            path=("Thumbnail", short_name),
                            raw_value=raw_v,
                            interpreted_value=interp_v,
                            data_type=dtype_v,
                            status=MetadataStatus.PRESENT,
                            limitations=note_v,
                        )
                    )
                    continue

                if key_str.startswith("MakerNote "):
                    short_name = key_str[len("MakerNote ") :]
                    tag_id_hex = f"0x{tag_obj.tag:04X}" if hasattr(tag_obj, "tag") else None
                    raw_v, interp_v, dtype_v, note_v = _normalize_value(
                        getattr(tag_obj, "values", tag_obj),
                        getattr(tag_obj, "printable", None),
                    )
                    is_unk = short_name.startswith("Tag 0x")
                    mn_records.append(
                        MetadataRecord(
                            record_id=f"makernotes:{tag_id_hex or short_name}:{short_name}",
                            source="EXIF MakerNotes",
                            category="EXIF MakerNotes",
                            tag_name=short_name,
                            tag_id=tag_id_hex,
                            namespace="MakerNote",
                            path=("MakerNote", short_name),
                            raw_value=raw_v,
                            interpreted_value=interp_v,
                            data_type=dtype_v,
                            status=MetadataStatus.UNSUPPORTED if is_unk else MetadataStatus.PRESENT,
                            is_unknown=is_unk,
                            limitations=(
                                "Unrecognized manufacturer-specific MakerNote tag."
                                if is_unk
                                else note_v
                            ),
                        )
                    )
                    continue

                if " " in key_str:
                    ifd_name, short_name = key_str.split(" ", 1)
                else:
                    ifd_name, short_name = "EXIF", key_str

                if short_name == "MakerNote":
                    vals = getattr(tag_obj, "values", b"")
                    if isinstance(vals, (bytes, bytearray)):
                        raw_makernote_blob = bytes(vals)
                    elif isinstance(vals, list) and all(isinstance(x, int) for x in vals):
                        raw_makernote_blob = bytes(x & 0xFF for x in vals)
                    continue

                if short_name == "GPSInfo":
                    gps_present = True
                    continue

                tag_id_hex = f"0x{tag_obj.tag:04X}" if hasattr(tag_obj, "tag") else None
                raw_v, interp_v, dtype_v, note_v = _normalize_value(
                    getattr(tag_obj, "values", tag_obj),
                    getattr(tag_obj, "printable", None),
                )
                is_unk = short_name.startswith("Tag 0x")
                cat = (
                    "Unknown / Unclassified Metadata"
                    if is_unk
                    else _EXIF_CATEGORY_MAP.get(short_name, "EXIF Metadata")
                )
                seen_exif_tags.add(short_name)
                if short_name == "ExposureTime" and isinstance(raw_v, dict) and "numerator" in raw_v:
                    interp_v = f"{raw_v['numerator']}/{raw_v['denominator']} s"
                elif short_name == "FNumber" and isinstance(raw_v, dict) and raw_v.get("denominator"):
                    f_val = raw_v["numerator"] / raw_v["denominator"]
                    interp_v = f"f/{f_val:g}"
                elif short_name == "Orientation" and isinstance(raw_v, int) and interp_v and not interp_v.startswith(str(raw_v)):
                    interp_v = f"{raw_v} — {interp_v}"
                exif_records.append(
                    MetadataRecord(
                        record_id=f"exif:{ifd_name}:{tag_id_hex or short_name}:{short_name}",
                        source="EXIF",
                        category=cat,
                        tag_name=short_name,
                        tag_id=tag_id_hex,
                        namespace=ifd_name,
                        path=("EXIF", ifd_name, short_name),
                        raw_value=raw_v,
                        interpreted_value=interp_v,
                        data_type=dtype_v,
                        status=MetadataStatus.PRESENT,
                        is_unknown=is_unk,
                        limitations=note_v,
                    )
                )
        except Exception as exc:
            exif_warnings.append(MetadataExtractionWarning("exif", "EXIFREAD_ERROR", str(exc)))

    # Pillow EXIF fallback / additional IFD coverage (PNG, WebP, TIFF, and unmapped tags)
    try:
        with Image.open(BytesIO(file_bytes)) as img:
            exif = img.getexif()
            ifd_sources: list[tuple[str, dict[int, Any]]] = [("Image", dict(exif.items()))]
            for ifd_label, ifd_id in (("EXIF", ExifTags.IFD.Exif), ("Interop", ExifTags.IFD.Interop)):
                try:
                    ifd_sources.append((ifd_label, dict(exif.get_ifd(ifd_id))))
                except (AttributeError, KeyError, TypeError):
                    pass
            try:
                gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
                if gps_ifd:
                    gps_present = True
            except (AttributeError, KeyError, TypeError):
                pass

            for ifd_label, tag_dict in ifd_sources:
                for tag_id, val in sorted(tag_dict.items()):
                    if tag_id == 0x8825:  # GPSInfo pointer
                        gps_present = True
                        continue
                    tag_id_hex = f"0x{int(tag_id):04X}"
                    tag_name = ExifTags.TAGS.get(tag_id)
                    is_unk = tag_name is None
                    display_name = tag_name or f"Tag {tag_id_hex}"

                    if tag_id == 0x927C:  # MakerNote
                        if isinstance(val, (bytes, bytearray)) and raw_makernote_blob is None:
                            raw_makernote_blob = bytes(val)
                        continue

                    if display_name in seen_exif_tags:
                        continue
                    seen_exif_tags.add(display_name)
                    raw_v, interp_v, dtype_v, note_v = _normalize_value(val)
                    cat = (
                        "Unknown / Unclassified Metadata"
                        if is_unk
                        else _EXIF_CATEGORY_MAP.get(display_name, "EXIF Metadata")
                    )
                    exif_records.append(
                        MetadataRecord(
                            record_id=f"exif:{ifd_label}:{tag_id_hex}:{display_name}",
                            source="EXIF",
                            category=cat,
                            tag_name=display_name,
                            tag_id=tag_id_hex,
                            namespace=ifd_label,
                            path=("EXIF", ifd_label, display_name),
                            raw_value=raw_v,
                            interpreted_value=interp_v,
                            data_type=dtype_v,
                            status=MetadataStatus.PRESENT,
                            is_unknown=is_unk,
                            limitations=note_v,
                        )
                    )
    except Exception as exc:
        exif_warnings.append(MetadataExtractionWarning("exif", "PILLOW_EXIF_ERROR", str(exc)))

    has_decoded_mn = any(not r.is_unknown for r in mn_records)
    if raw_makernote_blob is not None and not has_decoded_mn:
        raw_b, _, _ = _truncate_bytes(raw_makernote_blob)
        mn_records.append(
            MetadataRecord(
                record_id="makernotes:0x927C:MakerNote",
                source="EXIF MakerNotes",
                category="EXIF MakerNotes",
                tag_name="MakerNote",
                tag_id="0x927C",
                namespace="ExifIFD",
                path=("ExifIFD", "MakerNote"),
                raw_value=raw_b,
                interpreted_value=f"Not decoded — raw MakerNote blob ({len(raw_makernote_blob)} bytes)",
                data_type="bytes",
                status=MetadataStatus.UNSUPPORTED,
                is_unknown=True,
                limitations="Manufacturer-specific MakerNotes could not be decoded by ExifRead; bounded raw preview preserved.",
            )
        )
    if (raw_makernote_blob is not None and not has_decoded_mn) or any(r.is_unknown for r in mn_records):
        mn_warnings.append(
            MetadataExtractionWarning(
                "makernotes",
                "MAKERNOTES_UNDECODED",
                "MakerNote tag 0x927C contains undecoded or unrecognized proprietary data.",
            )
        )

    exif_state = (
        StageCompletionState.PARTIAL
        if exif_warnings and exif_records
        else StageCompletionState.FAILED
        if exif_warnings
        else StageCompletionState.COMPLETED
        if exif_records
        else StageCompletionState.EMPTY
    )
    mn_state = (
        StageCompletionState.PARTIAL
        if mn_warnings
        else StageCompletionState.COMPLETED
        if mn_records
        else StageCompletionState.EMPTY
    )
    thumb_state = (
        StageCompletionState.COMPLETED
        if thumb_records
        else StageCompletionState.EMPTY
    )

    return (
        exif_records + mn_records + thumb_records,
        MetadataExtractionStage(
            stage_id="exif",
            source_standard="EXIF",
            completion_state=exif_state,
            records_extracted=len(exif_records),
            warnings=tuple(exif_warnings),
            limitations=("GPS IFD tags are excluded from ordinary metadata inventory.",),
        ),
        MetadataExtractionStage(
            stage_id="makernotes",
            source_standard="EXIF MakerNotes",
            completion_state=mn_state,
            records_extracted=len(mn_records),
            warnings=tuple(mn_warnings),
            unsupported_features=(
                ("Proprietary MakerNotes decoding",) if mn_warnings else ()
            ),
            limitations=("Manufacturer-specific MakerNotes are preserved raw when undecodable.",),
        ),
        MetadataExtractionStage(
            stage_id="thumbnail",
            source_standard="Thumbnail",
            completion_state=thumb_state,
            records_extracted=len(thumb_records),
            warnings=tuple(thumb_warnings),
            limitations=("Thumbnail metadata summarizes embedded preview presence and size.",),
        ),
        gps_present,
    )


def _split_xml_tag(tag: str) -> tuple[str | None, str]:
    if tag.startswith("{") and "}" in tag:
        ns, local = tag[1:].split("}", 1)
        return ns, local
    return None, tag


def _xml_node_to_structure(
    element: ET.Element, depth: int, counter: list[int], gps_flag: list[bool] | None = None
) -> Any:
    if depth > MAX_XMP_DEPTH or counter[0] >= MAX_XMP_NODES:
        return "[truncated]"
    _, local = _split_xml_tag(element.tag)
    if local.lower().startswith("gps"):
        if gps_flag is not None:
            gps_flag[0] = True
        return None
    counter[0] += 1
    children = list(element)
    if not children:
        return " ".join((element.text or "").split())

    if local in {"Bag", "Seq", "Alt"}:
        items = []
        for child in children[:64]:
            val = _xml_node_to_structure(child, depth + 1, counter, gps_flag)
            if val is not None:
                items.append(val)
        return items

    result: dict[str, Any] = {}
    for child in children[:64]:
        _, child_local = _split_xml_tag(child.tag)
        if child_local.lower().startswith("gps"):
            if gps_flag is not None:
                gps_flag[0] = True
            continue
        val = _xml_node_to_structure(child, depth + 1, counter, gps_flag)
        if val is None:
            continue
        if child_local in result:
            existing = result[child_local]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[child_local] = [existing, val]
        else:
            result[child_local] = val
    return result


def _extract_xmp_inventory(
    file_bytes: bytes, image_format: str
) -> tuple[list[MetadataRecord], MetadataExtractionStage, bool]:
    if image_format.upper() not in SUPPORTED_XMP_FORMATS:
        msg = f"XMP extraction is unsupported for {image_format}."
        return (
            [],
            MetadataExtractionStage("xmp", "XMP", StageCompletionState.UNSUPPORTED, 0, unsupported_features=(msg,), limitations=(msg,)),
            False,
        )

    warnings: list[MetadataExtractionWarning] = []
    partial_extended = False
    packet: bytes | None = None
    try:
        packet = _image_xmp(file_bytes, image_format.upper())
    except XMPUnsupportedLocationError as exc:
        partial_extended = True
        packet = exc.partial_packet
        warnings.append(MetadataExtractionWarning("xmp", "XMP_EXTENDED_DETECTED", str(exc)))
    except XMPReadError as exc:
        warnings.append(MetadataExtractionWarning("xmp", "XMP_READ_ERROR", str(exc)))
        return (
            [],
            MetadataExtractionStage("xmp", "XMP", StageCompletionState.FAILED, 0, warnings=tuple(warnings)),
            False,
        )

    if packet is None:
        state = StageCompletionState.PARTIAL if partial_extended else StageCompletionState.EMPTY
        return (
            [],
            MetadataExtractionStage("xmp", "XMP", state, 0, warnings=tuple(warnings)),
            False,
        )

    if len(packet) > XMP_MAX_BYTES or b"<!DOCTYPE" in packet.upper() or b"<!ENTITY" in packet.upper():
        warnings.append(MetadataExtractionWarning("xmp", "XMP_UNSAFE_OR_OVERSIZED", "XMP packet rejected by safety limits."))
        return (
            [],
            MetadataExtractionStage("xmp", "XMP", StageCompletionState.FAILED, 0, warnings=tuple(warnings)),
            False,
        )

    try:
        root = ET.fromstring(packet)
    except (ET.ParseError, ValueError, UnicodeError) as exc:
        warnings.append(MetadataExtractionWarning("xmp", "XMP_MALFORMED_XML", str(exc)))
        return (
            [],
            MetadataExtractionStage("xmp", "XMP", StageCompletionState.FAILED, 0, warnings=tuple(warnings)),
            False,
        )

    records: list[MetadataRecord] = []
    gps_present = False
    node_counter = [0]

    def walk(elem: ET.Element, path: tuple[str, ...], depth: int) -> None:
        nonlocal gps_present
        if depth > MAX_XMP_DEPTH or node_counter[0] >= MAX_XMP_NODES:
            return
        node_counter[0] += 1

        ns, local = _split_xml_tag(elem.tag)
        if local.lower().startswith("gps"):
            gps_present = True
            return

        attrs = tuple(
            (f"{_split_xml_tag(k)[1]}", " ".join(v.split()))
            for k, v in sorted(elem.attrib.items())
            if _split_xml_tag(k)[1] not in {"about"}
            and not _split_xml_tag(k)[1].lower().startswith("gps")
        )

        # Record attribute-stored XMP properties on Description elements
        for attr_k, attr_v in sorted(elem.attrib.items()):
            a_ns, a_local = _split_xml_tag(attr_k)
            if a_local.lower().startswith("gps"):
                gps_present = True
                continue
            if a_ns and a_ns not in {
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "http://www.w3.org/XML/1998/namespace",
            } and attr_v.strip():
                is_unk = a_ns not in _KNOWN_XMP_NAMESPACES
                records.append(
                    MetadataRecord(
                        record_id=f"xmp:{'/'.join(path)}/@{a_local}:{len(records)}",
                        source="XMP",
                        category="Unknown / Unclassified Metadata" if is_unk else "XMP Metadata",
                        tag_name=a_local,
                        namespace=a_ns,
                        path=path + (f"@{a_local}",),
                        raw_value=" ".join(attr_v.split()),
                        interpreted_value=" ".join(attr_v.split()),
                        data_type="string",
                        status=MetadataStatus.PRESENT,
                        is_unknown=is_unk,
                    )
                )

        # Skip wrapper containers and recurse directly
        if local in {"xmpmeta", "RDF", "Description"}:
            for idx, child in enumerate(elem):
                _, c_local = _split_xml_tag(child.tag)
                walk(child, path + (f"{c_local}[{idx}]",), depth + 1)
            return

        children = list(elem)
        is_unk = bool(ns and ns not in _KNOWN_XMP_NAMESPACES)
        cat = "Unknown / Unclassified Metadata" if is_unk else (
            "Software Information" if local == "CreatorTool" else "XMP Metadata"
        )
        if not children:
            text_val = " ".join((elem.text or "").split())
            if text_val or attrs:
                records.append(
                    MetadataRecord(
                        record_id=f"xmp:{'/'.join(path)}:{len(records)}",
                        source="XMP",
                        category=cat,
                        tag_name=local,
                        namespace=ns,
                        path=path,
                        raw_value=text_val,
                        interpreted_value=text_val or "(attributes only)",
                        data_type="string",
                        status=MetadataStatus.PRESENT,
                        is_unknown=is_unk,
                        is_hierarchical=len(path) > 2,
                        attributes=attrs,
                    )
                )
        else:
            nested_gps = [False]
            struct_val = _xml_node_to_structure(elem, depth, [0], nested_gps)
            if nested_gps[0]:
                gps_present = True
            dtype = "array" if isinstance(struct_val, list) else "struct"
            records.append(
                MetadataRecord(
                    record_id=f"xmp:{'/'.join(path)}:{len(records)}",
                    source="XMP",
                    category=cat,
                    tag_name=local,
                    namespace=ns,
                    path=path,
                    raw_value=struct_val,
                    interpreted_value=str(struct_val)[:240],
                    data_type=dtype,
                    status=MetadataStatus.PRESENT,
                    is_unknown=is_unk,
                    is_hierarchical=True,
                    attributes=attrs,
                )
            )
            for idx, child in enumerate(children):
                _, c_local = _split_xml_tag(child.tag)
                walk(child, path + (f"{c_local}[{idx}]",), depth + 1)

    walk(root, ("XMP",), 0)

    if node_counter[0] >= MAX_XMP_NODES:
        warnings.append(MetadataExtractionWarning("xmp", "XMP_NODE_LIMIT", f"XMP traversal capped at {MAX_XMP_NODES} nodes."))

    state = (
        StageCompletionState.PARTIAL
        if partial_extended or warnings
        else StageCompletionState.COMPLETED
        if records
        else StageCompletionState.EMPTY
    )
    return (
        records,
        MetadataExtractionStage(
            stage_id="xmp",
            source_standard="XMP",
            completion_state=state,
            records_extracted=len(records),
            warnings=tuple(warnings),
            unsupported_features=("Extended XMP multi-packet reassembly",) if partial_extended else (),
            limitations=("XMP GPS properties are excluded from ordinary metadata inventory.",),
        ),
        gps_present,
    )


def _extract_iptc_inventory(
    file_bytes: bytes, image_format: str
) -> tuple[list[MetadataRecord], MetadataExtractionStage]:
    if image_format.upper() not in SUPPORTED_IPTC_FORMATS:
        msg = f"IPTC extraction is unsupported for {image_format}."
        return (
            [],
            MetadataExtractionStage("iptc", "IPTC", StageCompletionState.UNSUPPORTED, 0, unsupported_features=(msg,), limitations=(msg,)),
        )

    warnings: list[MetadataExtractionWarning] = []
    try:
        resources = (
            _jpeg_iptc_resources(file_bytes)
            if image_format.upper() == "JPEG"
            else _tiff_iptc(file_bytes)
        )
    except IPTCReadError as exc:
        warnings.append(MetadataExtractionWarning("iptc", "IPTC_MALFORMED", str(exc)))
        return (
            [],
            MetadataExtractionStage("iptc", "IPTC", StageCompletionState.FAILED, 0, warnings=tuple(warnings)),
        )

    if not resources:
        return ([], MetadataExtractionStage("iptc", "IPTC", StageCompletionState.EMPTY, 0))

    datasets: dict[tuple[int, int], list[bytes]] = {}
    for resource in resources:
        try:
            parsed = _parse_iim(resource)
            for k, vals in parsed.items():
                datasets.setdefault(k, []).extend(vals)
        except IPTCReadError as exc:
            warnings.append(MetadataExtractionWarning("iptc", "IPTC_DATASET_ERROR", str(exc)))

    if not datasets and warnings:
        return (
            [],
            MetadataExtractionStage("iptc", "IPTC", StageCompletionState.FAILED, 0, warnings=tuple(warnings)),
        )

    coded_charset = datasets.get((1, 90), [])
    utf8 = b"\x1b%G" in coded_charset
    if coded_charset and not utf8 and any(val not in {b"\x1b%G", b""} for val in coded_charset):
        warnings.append(
            MetadataExtractionWarning(
                "iptc",
                "IPTC_UNSUPPORTED_ENCODING",
                "Unsupported IPTC character encoding escape sequence; decoded using Latin-1 fallback.",
            )
        )

    records: list[MetadataRecord] = []
    for (rec, ds), raw_list in sorted(datasets.items()):
        if (rec, ds) == (1, 90):
            continue
        decoded_vals = [_decode_dataset(b, utf8) for b in raw_list]
        decoded_vals = [v for v in decoded_vals if v]
        if not decoded_vals:
            continue
        known_name = _IPTC_DATASET_NAMES.get((rec, ds))
        is_unk = known_name is None
        tag_name = known_name or f"Dataset {rec}:{ds}"
        raw_val: Any = decoded_vals if len(decoded_vals) > 1 else decoded_vals[0]
        dtype = "array" if len(decoded_vals) > 1 else "string"
        records.append(
            MetadataRecord(
                record_id=f"iptc:{rec}:{ds}",
                source="IPTC",
                category="Unknown / Unclassified Metadata" if is_unk else "IPTC Metadata",
                tag_name=tag_name,
                tag_id=f"{rec}:{ds}",
                namespace=f"Record {rec}",
                path=("IPTC", f"Record {rec}", f"{rec}:{ds}"),
                raw_value=raw_val,
                interpreted_value="; ".join(decoded_vals),
                data_type=dtype,
                status=MetadataStatus.PRESENT,
                is_unknown=is_unk,
            )
        )

    state = StageCompletionState.PARTIAL if warnings else StageCompletionState.COMPLETED
    return (
        records,
        MetadataExtractionStage(
            stage_id="iptc",
            source_standard="IPTC",
            completion_state=state,
            records_extracted=len(records),
            warnings=tuple(warnings),
        ),
    )


def _extract_icc_inventory(file_bytes: bytes) -> tuple[list[MetadataRecord], MetadataExtractionStage]:
    try:
        with Image.open(BytesIO(file_bytes)) as img:
            icc_bytes = img.info.get("icc_profile")
    except (OSError, ValueError) as exc:
        return (
            [],
            MetadataExtractionStage(
                "icc",
                "ICC",
                StageCompletionState.FAILED,
                0,
                warnings=(MetadataExtractionWarning("icc", "ICC_READ_ERROR", str(exc)),),
            ),
        )

    if not icc_bytes:
        return ([], MetadataExtractionStage("icc", "ICC", StageCompletionState.EMPTY, 0))

    if len(icc_bytes) > MAX_ICC_BYTES:
        return (
            [],
            MetadataExtractionStage(
                "icc",
                "ICC",
                StageCompletionState.SKIPPED_RESOURCE_LIMIT,
                0,
                warnings=(MetadataExtractionWarning("icc", "ICC_OVERSIZED", "ICC profile exceeds 4 MB limit."),),
            ),
        )

    records: list[MetadataRecord] = []
    warnings: list[MetadataExtractionWarning] = []

    if len(icc_bytes) >= 68:
        try:
            size, cmm, ver, dev_class, color_sp, pcs, *_ = struct.unpack(
                ">I4sI4s4s4s3H12s4s4sI4s", icc_bytes[:68]
            )
            major = (ver >> 24) & 0xFF
            minor = (ver >> 20) & 0x0F
            bugfix = (ver >> 16) & 0x0F
            header_items = [
                ("ProfileSizeBytes", "Profile size (bytes)", size, "integer"),
                ("ProfileVersion", "Profile version", f"{major}.{minor}.{bugfix}", "string"),
                ("PreferredCMM", "Preferred CMM", cmm.decode("ascii", errors="replace").strip("\x00 "), "string"),
                ("DeviceClass", "Device class", dev_class.decode("ascii", errors="replace").strip(), "string"),
                ("ColorSpace", "Profile colour space", color_sp.decode("ascii", errors="replace").strip(), "string"),
                ("ConnectionSpace", "Profile connection space", pcs.decode("ascii", errors="replace").strip(), "string"),
            ]
            for tag_name, label, val, dtype in header_items:
                records.append(
                    MetadataRecord(
                        record_id=f"icc:header:{tag_name}",
                        source="ICC",
                        category="ICC Colour Profile",
                        tag_name=label,
                        namespace="ICC Header",
                        path=("ICC", tag_name),
                        raw_value=val,
                        interpreted_value=str(val),
                        data_type=dtype,
                        status=MetadataStatus.PRESENT,
                    )
                )
        except struct.error as exc:
            warnings.append(MetadataExtractionWarning("icc", "ICC_HEADER_ERROR", str(exc)))

    try:
        profile = ImageCms.ImageCmsProfile(BytesIO(icc_bytes))
        desc = ImageCms.getProfileDescription(profile).strip()
        if desc:
            records.append(
                MetadataRecord(
                    record_id="icc:tag:desc",
                    source="ICC",
                    category="ICC Colour Profile",
                    tag_name="Profile description",
                    tag_id="desc",
                    namespace="ICC",
                    path=("ICC", "desc"),
                    raw_value=desc,
                    interpreted_value=desc,
                    data_type="string",
                    status=MetadataStatus.PRESENT,
                )
            )
        copyright_txt = ImageCms.getProfileCopyright(profile).strip()
        if copyright_txt:
            records.append(
                MetadataRecord(
                    record_id="icc:tag:cprt",
                    source="ICC",
                    category="ICC Colour Profile",
                    tag_name="Profile copyright",
                    tag_id="cprt",
                    namespace="ICC",
                    path=("ICC", "cprt"),
                    raw_value=copyright_txt,
                    interpreted_value=copyright_txt,
                    data_type="string",
                    status=MetadataStatus.PRESENT,
                )
            )
    except Exception as exc:
        warnings.append(MetadataExtractionWarning("icc", "ICC_PARSE_ERROR", str(exc)))

    state = (
        StageCompletionState.PARTIAL
        if warnings and records
        else StageCompletionState.FAILED
        if warnings
        else StageCompletionState.COMPLETED
    )
    return (
        records,
        MetadataExtractionStage(
            stage_id="icc",
            source_standard="ICC",
            completion_state=state,
            records_extracted=len(records),
            warnings=tuple(warnings),
        ),
    )


def extract_metadata_inventory(
    file_bytes: bytes,
    image_format: str,
    properties: ImageProperties,
    *,
    enable_exiftool: bool = True,
) -> MetadataInventory:
    """Extract a bounded, non-GPS metadata inventory and measurable coverage report."""
    internal_records: list[MetadataRecord] = []
    stages: list[MetadataExtractionStage] = []
    all_warnings: list[MetadataExtractionWarning] = []
    gps_present = False

    sig_info = identify_file_signature(file_bytes, properties.filename)

    t0 = time.monotonic()
    container_recs, container_stage = _extract_container(file_bytes, properties)
    container_dur = (time.monotonic() - t0) * 1000.0
    internal_records.extend(container_recs)
    stages.append(
        MetadataExtractionStage(
            stage_id=container_stage.stage_id,
            source_standard=container_stage.source_standard,
            completion_state=container_stage.completion_state,
            records_extracted=container_stage.records_extracted,
            warnings=container_stage.warnings,
            unsupported_features=container_stage.unsupported_features,
            limitations=container_stage.limitations,
            engine_name=f"Pillow + {image_format} Container Parser",
            engine_version=getattr(Image, "__version__", None),
            availability="Available",
            duration_ms=container_dur,
        )
    )

    t0 = time.monotonic()
    exif_recs, exif_stage, mn_stage, thumb_stage, exif_gps = _extract_exif_makernotes_thumbnail(
        file_bytes, image_format
    )
    exif_dur = (time.monotonic() - t0) * 1000.0
    internal_records.extend(exif_recs)
    for st in (exif_stage, mn_stage, thumb_stage):
        stages.append(
            MetadataExtractionStage(
                stage_id=st.stage_id,
                source_standard=st.source_standard,
                completion_state=st.completion_state,
                records_extracted=st.records_extracted,
                warnings=st.warnings,
                unsupported_features=st.unsupported_features,
                limitations=st.limitations,
                engine_name="exifread + Pillow EXIF",
                engine_version=getattr(exifread, "__version__", None),
                availability="Unsupported" if st.completion_state is StageCompletionState.UNSUPPORTED else "Available",
                duration_ms=exif_dur if st.stage_id == "exif" else 0.0,
            )
        )
    gps_present = gps_present or exif_gps

    t0 = time.monotonic()
    xmp_recs, xmp_stage, xmp_gps = _extract_xmp_inventory(file_bytes, image_format)
    xmp_dur = (time.monotonic() - t0) * 1000.0
    internal_records.extend(xmp_recs)
    stages.append(
        MetadataExtractionStage(
            stage_id=xmp_stage.stage_id,
            source_standard=xmp_stage.source_standard,
            completion_state=xmp_stage.completion_state,
            records_extracted=xmp_stage.records_extracted,
            warnings=xmp_stage.warnings,
            unsupported_features=xmp_stage.unsupported_features,
            limitations=xmp_stage.limitations,
            engine_name="Native XMP Parser",
            availability="Unsupported" if xmp_stage.completion_state is StageCompletionState.UNSUPPORTED else "Available",
            duration_ms=xmp_dur,
        )
    )
    gps_present = gps_present or xmp_gps

    t0 = time.monotonic()
    iptc_recs, iptc_stage = _extract_iptc_inventory(file_bytes, image_format)
    iptc_dur = (time.monotonic() - t0) * 1000.0
    internal_records.extend(iptc_recs)
    stages.append(
        MetadataExtractionStage(
            stage_id=iptc_stage.stage_id,
            source_standard=iptc_stage.source_standard,
            completion_state=iptc_stage.completion_state,
            records_extracted=iptc_stage.records_extracted,
            warnings=iptc_stage.warnings,
            unsupported_features=iptc_stage.unsupported_features,
            limitations=iptc_stage.limitations,
            engine_name="Native IPTC Parser",
            availability="Unsupported" if iptc_stage.completion_state is StageCompletionState.UNSUPPORTED else "Available",
            duration_ms=iptc_dur,
        )
    )

    t0 = time.monotonic()
    icc_recs, icc_stage = _extract_icc_inventory(file_bytes)
    icc_dur = (time.monotonic() - t0) * 1000.0
    internal_records.extend(icc_recs)
    stages.append(
        MetadataExtractionStage(
            stage_id=icc_stage.stage_id,
            source_standard=icc_stage.source_standard,
            completion_state=icc_stage.completion_state,
            records_extracted=icc_stage.records_extracted,
            warnings=icc_stage.warnings,
            unsupported_features=icc_stage.unsupported_features,
            limitations=icc_stage.limitations,
            engine_name="Pillow ImageCms (ICC)",
            availability="Available",
            duration_ms=icc_dur,
        )
    )

    et_available = False
    if enable_exiftool:
        et_res = run_exiftool(file_bytes, properties.filename)
        et_available = et_res.status.available
        gps_present = gps_present or et_res.gps_present_indicator
        if et_res.execution_status == "UNAVAILABLE":
            et_state = StageCompletionState.UNSUPPORTED
            et_avail_label = "Unavailable"
        elif et_res.execution_status == "COMPLETED":
            et_state = StageCompletionState.COMPLETED
            et_avail_label = "Available"
        elif et_res.execution_status == "EMPTY":
            et_state = StageCompletionState.EMPTY
            et_avail_label = "Available"
        elif et_res.execution_status == "SKIPPED_RESOURCE_LIMIT":
            et_state = StageCompletionState.SKIPPED_RESOURCE_LIMIT
            et_avail_label = "Available"
        else:
            et_state = StageCompletionState.FAILED
            et_avail_label = "Available"
        stages.append(
            MetadataExtractionStage(
                stage_id="exiftool",
                source_standard="ExifTool",
                completion_state=et_state,
                records_extracted=len(et_res.records),
                warnings=et_res.warnings,
                unsupported_features=() if et_available else (et_res.status.reason,),
                limitations=(
                    ("ExifTool GPS group tags are excluded from ordinary metadata inventory.",)
                    if et_available
                    else (et_res.status.reason,)
                ),
                engine_name="ExifTool",
                engine_version=et_res.status.version,
                availability=et_avail_label,
                duration_ms=et_res.duration_ms,
                errors=(et_res.error,) if et_res.error else (),
            )
        )
        all_records = list(merge_metadata_records(internal_records, et_res.records))
    else:
        all_records = list(merge_metadata_records(internal_records))

    for stage in stages:
        all_warnings.extend(stage.warnings)

    if len(all_records) > MAX_METADATA_RECORDS:
        all_records = all_records[:MAX_METADATA_RECORDS]
        all_warnings.append(
            MetadataExtractionWarning(
                "inventory",
                "RECORD_LIMIT_REACHED",
                f"Inventory capped at {MAX_METADATA_RECORDS} records.",
            )
        )

    categories_found = tuple(dict.fromkeys(r.category for r in all_records))
    unsupported_sources = tuple(
        s.source_standard
        for s in stages
        if s.completion_state is StageCompletionState.UNSUPPORTED and s.stage_id != "exiftool"
    )
    limitations_list = list(GLOBAL_LIMITATIONS)
    if all(s.records_extracted == 0 for s in stages if s.stage_id in {"exif", "xmp", "iptc"}):
        limitations_list.append(
            "Some metadata may have been removed or was not present in this image. "
            "PIXELTRUTH extracted the information that remains available."
        )
    format_cap = get_format_capability(image_format, exiftool_available=et_available)
    coverage = MetadataExtractionCoverage(
        total_records=len(all_records),
        categories_found=categories_found,
        unsupported_sources=unsupported_sources,
        stages=tuple(stages),
        warnings=tuple(all_warnings),
        limitations=tuple(limitations_list),
        format_capability=format_cap.to_dict(),
        file_signature=sig_info.to_dict(),
    )
    return MetadataInventory(
        records=tuple(all_records),
        coverage=coverage,
        gps_present_indicator=gps_present,
    )
