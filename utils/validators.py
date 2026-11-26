"""Content-based image validation and resource limits."""

from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
import warnings

from PIL import Image, UnidentifiedImageError


MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_IMAGE_PIXELS = 80_000_000
MAX_TOTAL_FRAME_PIXELS = 120_000_000
MAX_FRAME_COUNT = 200

SUPPORTED_FORMATS = {"JPEG", "PNG", "WEBP", "TIFF", "BMP", "GIF"}
SUPPORTED_EXTENSIONS = ("jpg", "jpeg", "png", "webp", "tif", "tiff", "bmp", "gif")
FORMAT_MIME_TYPES = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
    "TIFF": "image/tiff",
    "BMP": "image/bmp",
    "GIF": "image/gif",
}
FORMAT_EXTENSIONS = {
    "JPEG": {".jpg", ".jpeg"},
    "PNG": {".png"},
    "WEBP": {".webp"},
    "TIFF": {".tif", ".tiff"},
    "BMP": {".bmp"},
    "GIF": {".gif"},
}


class ImageValidationError(ValueError):
    """An uploaded file is not a safely supported image."""


@dataclass(frozen=True)
class ValidatedImage:
    image_format: str
    width: int
    height: int
    frame_dimensions: tuple[tuple[int, int], ...]
    color_mode: str
    frame_count: int
    has_transparency: bool
    bit_depth_per_channel: int | None
    extension_mismatch: bool


def _safe_filename(filename: str) -> str:
    """Reduce a client-provided name to a basename without path components."""
    normalized = (filename or "upload").replace("\\", "/")
    return PurePosixPath(normalized).name or "upload"


def _bit_depth(image: Image.Image) -> int | None:
    """Report a channel bit depth only for modes with a known mapping."""
    try:
        bits = image.tag_v2.get(258)  # TIFF BitsPerSample, if present.
        if isinstance(bits, (tuple, list)) and bits:
            values = {int(value) for value in bits}
            return values.pop() if len(values) == 1 else max(values)
        if bits is not None:
            return int(bits)
    except (AttributeError, TypeError, ValueError):
        pass

    return {
        "1": 1,
        "L": 8,
        "RGB": 8,
        "RGBA": 8,
        "CMYK": 8,
        "YCbCr": 8,
        "I;16": 16,
        "I;16B": 16,
        "I;16L": 16,
    }.get(image.mode)


def validate_image_bytes(
    file_bytes: bytes,
    filename: str,
    *,
    max_upload_bytes: int = MAX_UPLOAD_BYTES,
    max_image_pixels: int = MAX_IMAGE_PIXELS,
    max_total_frame_pixels: int = MAX_TOTAL_FRAME_PIXELS,
    max_frame_count: int = MAX_FRAME_COUNT,
) -> ValidatedImage:
    """Detect format from content, validate decoding, and enforce resource limits."""
    if not isinstance(file_bytes, bytes) or not file_bytes:
        raise ImageValidationError("The selected file is empty or unavailable.")
    if len(file_bytes) > max_upload_bytes:
        raise ImageValidationError(
            f"The file is larger than the {max_upload_bytes // (1024 * 1024)} MB upload limit."
        )

    safe_name = _safe_filename(filename)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(file_bytes)) as probe:
                detected_format = (probe.format or "").upper()
                if detected_format not in SUPPORTED_FORMATS:
                    raise ImageValidationError(
                        f"The detected format ({detected_format or 'unknown'}) is not supported."
                    )
                width, height = probe.size
                if width <= 0 or height <= 0:
                    raise ImageValidationError("The image has invalid dimensions.")
                frame_count = int(getattr(probe, "n_frames", 1))
                if frame_count < 1 or frame_count > max_frame_count:
                    raise ImageValidationError("The image exceeds the supported frame-count limit.")

                frame_dimensions = []
                total_frame_pixels = 0
                for index in range(frame_count):
                    probe.seek(index)
                    frame_width, frame_height = probe.size
                    if frame_width <= 0 or frame_height <= 0:
                        raise ImageValidationError("The image has invalid frame dimensions.")
                    frame_pixels = frame_width * frame_height
                    if frame_pixels > max_image_pixels:
                        raise ImageValidationError("The image exceeds the pixel-count safety limit.")
                    total_frame_pixels += frame_pixels
                    if total_frame_pixels > max_total_frame_pixels:
                        raise ImageValidationError("The image exceeds the total decoded-pixel limit.")
                    frame_dimensions.append((frame_width, frame_height))

                probe.seek(0)
                probe.verify()

            # verify() checks the container; decode each bounded frame to catch
            # truncated/corrupt pixel data before analysis modules consume it.
            with Image.open(BytesIO(file_bytes)) as decoded:
                for index, expected_dimensions in enumerate(frame_dimensions):
                    decoded.seek(index)
                    if decoded.size != expected_dimensions:
                        raise ImageValidationError("Image frame dimensions changed during validation.")
                    decoded.load()
                has_transparency = (
                    "A" in decoded.getbands()
                    or "transparency" in decoded.info
                )
                mode = decoded.mode
                bit_depth = _bit_depth(decoded)
    except ImageValidationError:
        raise
    except Image.DecompressionBombError as exc:
        raise ImageValidationError("The image exceeds the pixel-count safety limit.") from exc
    except (
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        EOFError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise ImageValidationError(
            "The file is not a supported, fully decodable image. Check the file and try again."
        ) from exc

    suffix = PurePosixPath(safe_name).suffix.lower()
    expected_extensions = FORMAT_EXTENSIONS[detected_format]
    return ValidatedImage(
        image_format=detected_format,
        width=width,
        height=height,
        frame_dimensions=tuple(frame_dimensions),
        color_mode=mode,
        frame_count=frame_count,
        has_transparency=has_transparency,
        bit_depth_per_channel=bit_depth,
        extension_mismatch=suffix not in expected_extensions,
    )
