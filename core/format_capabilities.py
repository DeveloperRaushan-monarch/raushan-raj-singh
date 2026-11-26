"""Content-based file signature identification and universal format capability registry."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any


class SupportLevel(str, Enum):
    FULLY_SUPPORTED = "FULLY_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    METADATA_ONLY = "METADATA_ONLY"
    IDENTIFIED_ONLY = "IDENTIFIED_ONLY"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class FileSignatureResult:
    """Content-based file identification independent of filename extension."""

    detected_format: str
    mime_type: str
    extension: str
    signature_hex: str
    signature_description: str
    extension_mismatch: bool
    identification_method: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_format": self.detected_format,
            "mime_type": self.mime_type,
            "extension": self.extension,
            "signature_hex": self.signature_hex,
            "signature_description": self.signature_description,
            "extension_mismatch": self.extension_mismatch,
            "identification_method": self.identification_method,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class FormatCapability:
    """Explicit capability matrix for a given image format under active engines."""

    format_name: str
    support_level: SupportLevel
    detection_support: bool
    metadata_extraction_support: bool
    pixel_decoding_support: bool
    structural_parsing_support: bool
    animation_support: bool
    exif_support: bool
    gps_support: bool
    xmp_support: bool
    icc_support: bool
    raw_support: bool
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_name": self.format_name,
            "support_level": self.support_level.value,
            "detection_support": self.detection_support,
            "metadata_extraction_support": self.metadata_extraction_support,
            "pixel_decoding_support": self.pixel_decoding_support,
            "structural_parsing_support": self.structural_parsing_support,
            "animation_support": self.animation_support,
            "exif_support": self.exif_support,
            "gps_support": self.gps_support,
            "xmp_support": self.xmp_support,
            "icc_support": self.icc_support,
            "raw_support": self.raw_support,
            "notes": list(self.notes),
        }


_FORMAT_META: dict[str, tuple[str, set[str]]] = {
    "JPEG": ("image/jpeg", {".jpg", ".jpeg", ".jpe"}),
    "PNG": ("image/png", {".png"}),
    "WEBP": ("image/webp", {".webp"}),
    "TIFF": ("image/tiff", {".tif", ".tiff"}),
    "GIF": ("image/gif", {".gif"}),
    "BMP": ("image/bmp", {".bmp"}),
    "HEIC": ("image/heic", {".heic", ".heif"}),
    "AVIF": ("image/avif", {".avif"}),
    "JXL": ("image/jxl", {".jxl"}),
    "RAW_CR2": ("image/x-canon-cr2", {".cr2"}),
    "RAW_DNG": ("image/x-adobe-dng", {".dng"}),
    "RAW_NEF": ("image/x-nikon-nef", {".nef"}),
    "RAW_ARW": ("image/x-sony-arw", {".arw"}),
    "RAW_RAF": ("image/x-fuji-raf", {".raf"}),
    "RAW_ORF": ("image/x-olympus-orf", {".orf"}),
    "RAW_RW2": ("image/x-panasonic-rw2", {".rw2"}),
}


def identify_file_signature(file_bytes: bytes, filename: str = "") -> FileSignatureResult:
    """Identify image format from magic bytes rather than filename extension."""
    normalized = (filename or "").replace("\\", "/")
    ext = PurePosixPath(normalized).suffix.lower()
    sig_hex = " ".join(f"{b:02X}" for b in file_bytes[:16])

    detected = "UNKNOWN"
    sig_desc = "Unrecognized binary signature"
    method = "magic-bytes"
    confidence = "LOW"

    if file_bytes.startswith(b"\xff\xd8\xff"):
        detected = "JPEG"
        sig_desc = "JPEG SOI + marker (FF D8 FF)"
        confidence = "HIGH"
    elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "PNG"
        sig_desc = "PNG 8-byte signature (89 50 4E 47 0D 0A 1A 0A)"
        confidence = "HIGH"
    elif len(file_bytes) >= 12 and file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        detected = "WEBP"
        sig_desc = "RIFF WEBP container"
        confidence = "HIGH"
    elif file_bytes.startswith((b"GIF87a", b"GIF89a")):
        detected = "GIF"
        sig_desc = f"GIF header ({file_bytes[:6].decode('ascii')})"
        confidence = "HIGH"
    elif file_bytes.startswith(b"BM"):
        detected = "BMP"
        sig_desc = "BMP bitmap header (42 4D)"
        confidence = "HIGH"
    elif file_bytes.startswith(b"FUJIFILMCCD-RAW"):
        detected = "RAW_RAF"
        sig_desc = "Fujifilm RAF RAW header"
        confidence = "HIGH"
    elif len(file_bytes) >= 12 and file_bytes[:4] == b"II*\x00" and file_bytes[8:12] == b"CR\x02\x00":
        detected = "RAW_CR2"
        sig_desc = "Canon CR2 (TIFF little-endian + CR2 signature)"
        confidence = "HIGH"
    elif file_bytes.startswith((b"II*\x00", b"MM\x00*")):
        # Differentiate common RAW extensions on TIFF-based containers only as hint
        if ext == ".dng":
            detected = "RAW_DNG"
            sig_desc = "TIFF-based DNG container"
        elif ext == ".nef":
            detected = "RAW_NEF"
            sig_desc = "TIFF-based Nikon NEF container"
        elif ext == ".arw":
            detected = "RAW_ARW"
            sig_desc = "TIFF-based Sony ARW container"
        else:
            detected = "TIFF"
            sig_desc = (
                "TIFF little-endian (49 49 2A 00)"
                if file_bytes.startswith(b"II*\x00")
                else "TIFF big-endian (4D 4D 00 2A)"
            )
        confidence = "HIGH"
    elif file_bytes.startswith(b"IIU\x00"):
        detected = "RAW_RW2"
        sig_desc = "Panasonic RW2 RAW header"
        confidence = "HIGH"
    elif file_bytes.startswith(b"IIRO"):
        detected = "RAW_ORF"
        sig_desc = "Olympus ORF RAW header"
        confidence = "HIGH"
    elif file_bytes.startswith((b"\xff\x0a", b"\x00\x00\x00\x0cJXL \r\n\x87\n")):
        detected = "JXL"
        sig_desc = "JPEG XL codestream/container"
        confidence = "HIGH"
    elif len(file_bytes) >= 12 and file_bytes[4:8] == b"ftyp":
        brand = file_bytes[8:12]
        if brand in {b"avif", b"avis"}:
            detected = "AVIF"
            sig_desc = f"ISO BMFF AVIF (ftyp{brand.decode('ascii', errors='replace')})"
            confidence = "HIGH"
        elif brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}:
            detected = "HEIC"
            sig_desc = f"ISO BMFF HEIC/HEIF (ftyp{brand.decode('ascii', errors='replace')})"
            confidence = "HIGH"

    mime, expected_exts = _FORMAT_META.get(detected, ("application/octet-stream", set()))
    mismatch = bool(ext and expected_exts and ext not in expected_exts)
    return FileSignatureResult(
        detected_format=detected,
        mime_type=mime,
        extension=ext or "(none)",
        signature_hex=sig_hex,
        signature_description=sig_desc,
        extension_mismatch=mismatch,
        identification_method=method,
        confidence=confidence,
    )


def get_format_capability(
    fmt: str,
    *,
    exiftool_available: bool = False,
    pillow_decodable: bool | None = None,
) -> FormatCapability:
    """Return explicit capability level and per-feature support for a format."""
    norm = (fmt or "").upper()
    if pillow_decodable is None:
        pillow_decodable = norm in {"JPEG", "PNG", "WEBP", "TIFF", "GIF", "BMP"}

    if norm == "JPEG":
        return FormatCapability(
            format_name="JPEG",
            support_level=SupportLevel.FULLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=False,
            exif_support=True,
            gps_support=True,
            xmp_support=True,
            icc_support=True,
            raw_support=False,
            notes=("Native JPEG APP/SOF segment parser + Pillow + ExifTool (when available).",),
        )
    if norm == "PNG":
        return FormatCapability(
            format_name="PNG",
            support_level=SupportLevel.FULLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=True,
            exif_support=True,
            gps_support=True,
            xmp_support=True,
            icc_support=True,
            raw_support=False,
            notes=("Native PNG chunk/CRC parser + Pillow + ExifTool (when available).",),
        )
    if norm == "WEBP":
        return FormatCapability(
            format_name="WEBP",
            support_level=SupportLevel.FULLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=True,
            exif_support=True,
            gps_support=True,
            xmp_support=True,
            icc_support=True,
            raw_support=False,
            notes=("Native RIFF/WebP chunk parser + Pillow + ExifTool (when available).",),
        )
    if norm == "TIFF":
        return FormatCapability(
            format_name="TIFF",
            support_level=SupportLevel.FULLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=False,
            exif_support=True,
            gps_support=True,
            xmp_support=True,
            icc_support=True,
            raw_support=False,
            notes=("Native TIFF header/IFD parser + Pillow + ExifTool (when available).",),
        )
    if norm == "GIF":
        return FormatCapability(
            format_name="GIF",
            support_level=SupportLevel.PARTIALLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=True,
            exif_support=False,
            gps_support=False,
            xmp_support=True,
            icc_support=False,
            raw_support=False,
            notes=("GIF does not natively carry EXIF or GPS IFDs; structural & animation metadata supported.",),
        )
    if norm == "BMP":
        return FormatCapability(
            format_name="BMP",
            support_level=SupportLevel.PARTIALLY_SUPPORTED,
            detection_support=True,
            metadata_extraction_support=True,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=True,
            animation_support=False,
            exif_support=False,
            gps_support=False,
            xmp_support=False,
            icc_support=False,
            raw_support=False,
            notes=("BMP carries DIB header properties; EXIF/XMP/IPTC are not standard.",),
        )
    if norm in {"HEIC", "AVIF", "JXL"}:
        if exiftool_available and pillow_decodable:
            level = SupportLevel.PARTIALLY_SUPPORTED
        elif exiftool_available:
            level = SupportLevel.METADATA_ONLY
        else:
            level = SupportLevel.IDENTIFIED_ONLY
        return FormatCapability(
            format_name=norm,
            support_level=level,
            detection_support=True,
            metadata_extraction_support=exiftool_available,
            pixel_decoding_support=pillow_decodable,
            structural_parsing_support=norm in {"HEIC", "AVIF"},
            animation_support=False,
            exif_support=exiftool_available,
            gps_support=exiftool_available,
            xmp_support=exiftool_available,
            icc_support=exiftool_available,
            raw_support=False,
            notes=("Requires ExifTool for full ISO BMFF/JXL metadata and optional decoder plugins for pixels.",),
        )
    if norm.startswith("RAW_"):
        return FormatCapability(
            format_name=norm,
            support_level=SupportLevel.METADATA_ONLY if exiftool_available else SupportLevel.IDENTIFIED_ONLY,
            detection_support=True,
            metadata_extraction_support=exiftool_available,
            pixel_decoding_support=False,
            structural_parsing_support=False,
            animation_support=False,
            exif_support=exiftool_available,
            gps_support=exiftool_available,
            xmp_support=exiftool_available,
            icc_support=exiftool_available,
            raw_support=True,
            notes=("Camera RAW pixel decoding is not performed; metadata extraction requires ExifTool.",),
        )
    return FormatCapability(
        format_name=norm or "UNKNOWN",
        support_level=SupportLevel.UNSUPPORTED,
        detection_support=False,
        metadata_extraction_support=False,
        pixel_decoding_support=False,
        structural_parsing_support=False,
        animation_support=False,
        exif_support=False,
        gps_support=False,
        xmp_support=False,
        icc_support=False,
        raw_support=False,
        notes=("Format is not supported by installed engines.",),
    )
