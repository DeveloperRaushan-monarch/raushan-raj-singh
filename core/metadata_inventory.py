"""Comprehensive, bounded, non-GPS metadata inventory extraction (Phase 6C)."""

from __future__ import annotations

from io import BytesIO
import struct
from typing import Any
import xml.etree.ElementTree as ET

import exifread
from PIL import ExifTags, Image, ImageCms

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


def _extract_container(
    file_bytes: bytes, properties: ImageProperties
) -> tuple[list[MetadataRecord], MetadataExtractionStage]:
    records: list[MetadataRecord] = []
    warnings: list[MetadataExtractionWarning] = []
    magic = file_bytes[:16].hex(" ").upper()

    file_items = [
        ("FileSignature", "File signature (magic bytes)", magic, "string"),
        ("DetectedFormat", "Detected format", properties.image_format, "string"),
        ("MimeType", "MIME type", properties.mime_type, "string"),
        ("FileSizeBytes", "File size (bytes)", properties.file_size_bytes, "integer"),
        ("ExtensionMismatch", "Extension mismatch", properties.extension_mismatch, "boolean"),
    ]
    for name, label, val, dtype in file_items:
        records.append(
            MetadataRecord(
                record_id=f"container:file:{name}",
                source="Container",
                category="File Information",
                tag_name=label,
                namespace="File",
                path=("File", name),
                raw_value=val,
                interpreted_value=str(val),
                data_type=dtype,
                status=MetadataStatus.PRESENT,
            )
        )

    img_items = [
        ("Width", "Image width (px)", properties.width, "integer"),
        ("Height", "Image height (px)", properties.height, "integer"),
        ("ColorMode", "Colour mode", properties.color_mode, "string"),
        ("FrameCount", "Frame count", properties.frame_count, "integer"),
        ("HasTransparency", "Transparency", properties.has_transparency, "boolean"),
    ]
    if properties.bit_depth_per_channel is not None:
        img_items.append(("BitDepth", "Bit depth per channel", properties.bit_depth_per_channel, "integer"))

    for name, label, val, dtype in img_items:
        records.append(
            MetadataRecord(
                record_id=f"container:image:{name}",
                source="Container",
                category="Image Information",
                tag_name=label,
                namespace="Container",
                path=("Container", name),
                raw_value=val,
                interpreted_value=str(val),
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
                cat = "Software Information" if key_str.lower() == "software" else "Image Information"
                records.append(
                    MetadataRecord(
                        record_id=f"container:info:{key_str}",
                        source="Container",
                        category=cat,
                        tag_name=key_str,
                        namespace="ContainerInfo",
                        path=("ContainerInfo", key_str),
                        raw_value=raw_v,
                        interpreted_value=interp_v,
                        data_type=dtype_v,
                        status=MetadataStatus.PRESENT,
                        limitations=note_v,
                    )
                )
    except (OSError, ValueError, TypeError) as exc:
        warnings.append(MetadataExtractionWarning("container", "CONTAINER_INFO_PARTIAL", str(exc)))

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
                exif_records.append(
                    MetadataRecord(
                        record_id=f"exif:{ifd_name}:{tag_id_hex or short_name}:{short_name}",
                        source="EXIF",
                        category=cat,
                        tag_name=short_name,
                        tag_id=tag_id_hex,
                        namespace=ifd_name,
                        path=(ifd_name, short_name),
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
                            path=(ifd_label, display_name),
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
) -> MetadataInventory:
    """Extract a bounded, non-GPS metadata inventory and measurable coverage report."""
    all_records: list[MetadataRecord] = []
    stages: list[MetadataExtractionStage] = []
    all_warnings: list[MetadataExtractionWarning] = []
    gps_present = False

    container_recs, container_stage = _extract_container(file_bytes, properties)
    all_records.extend(container_recs)
    stages.append(container_stage)

    exif_recs, exif_stage, mn_stage, thumb_stage, exif_gps = _extract_exif_makernotes_thumbnail(
        file_bytes, image_format
    )
    all_records.extend(exif_recs)
    stages.extend([exif_stage, mn_stage, thumb_stage])
    gps_present = gps_present or exif_gps

    xmp_recs, xmp_stage, xmp_gps = _extract_xmp_inventory(file_bytes, image_format)
    all_records.extend(xmp_recs)
    stages.append(xmp_stage)
    gps_present = gps_present or xmp_gps

    iptc_recs, iptc_stage = _extract_iptc_inventory(file_bytes, image_format)
    all_records.extend(iptc_recs)
    stages.append(iptc_stage)

    icc_recs, icc_stage = _extract_icc_inventory(file_bytes)
    all_records.extend(icc_recs)
    stages.append(icc_stage)

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
        s.source_standard for s in stages if s.completion_state is StageCompletionState.UNSUPPORTED
    )
    coverage = MetadataExtractionCoverage(
        total_records=len(all_records),
        categories_found=categories_found,
        unsupported_sources=unsupported_sources,
        stages=tuple(stages),
        warnings=tuple(all_warnings),
        limitations=GLOBAL_LIMITATIONS,
    )
    return MetadataInventory(
        records=tuple(all_records),
        coverage=coverage,
        gps_present_indicator=gps_present,
    )
