"""Bounded JPEG-only Error Level Analysis (ELA)."""

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, ImageChops, ImageEnhance, ImageOps, ImageStat, UnidentifiedImageError

from utils.validators import ImageValidationError, MAX_UPLOAD_BYTES, ValidatedImage, validate_image_bytes


MAX_ELA_PIXELS = 20_000_000
MIN_JPEG_QUALITY = 50
MAX_JPEG_QUALITY = 100
MIN_ERROR_SCALE = 1
MAX_ERROR_SCALE = 20


class ELAError(ValueError):
    """An ELA request could not be completed safely."""


class ELAUnsupportedFormatError(ELAError):
    """ELA was requested for a format other than JPEG."""


@dataclass(frozen=True)
class ELAResult:
    width: int
    height: int
    quality: int
    error_scale: int
    mean_absolute_difference: float
    maximum_channel_difference: int
    changed_pixel_percent: float
    residual_png: bytes
    method: str
    limitations: str


def apply_exif_orientation(image: Image.Image) -> Image.Image:
    """Return an image with its EXIF orientation applied for display or ELA."""
    return ImageOps.exif_transpose(image)


def calculate_ela(
    file_bytes: bytes,
    *,
    quality: int = 90,
    error_scale: int = 10,
    max_pixels: int = MAX_ELA_PIXELS,
) -> ELAResult:
    """Recompress a decoded JPEG once and return its amplified RGB residual.

    Inputs are content-validated. Images above ``max_pixels`` are rejected
    rather than resized, because resizing would change the residual being
    measured. ``max_pixels`` is injectable to keep boundary tests small.
    """
    if not isinstance(quality, int) or isinstance(quality, bool) or not MIN_JPEG_QUALITY <= quality <= MAX_JPEG_QUALITY:
        raise ELAError(f"JPEG quality must be between {MIN_JPEG_QUALITY} and {MAX_JPEG_QUALITY}.")
    if not isinstance(error_scale, int) or isinstance(error_scale, bool) or not MIN_ERROR_SCALE <= error_scale <= MAX_ERROR_SCALE:
        raise ELAError(f"Error scale must be between {MIN_ERROR_SCALE} and {MAX_ERROR_SCALE}.")
    if not isinstance(max_pixels, int) or isinstance(max_pixels, bool) or max_pixels < 1:
        raise ELAError("The ELA pixel limit must be a positive integer.")

    if not isinstance(file_bytes, bytes) or not file_bytes or len(file_bytes) > MAX_UPLOAD_BYTES:
        return _validate_ela_upload(file_bytes, max_pixels)
    try:
        with Image.open(BytesIO(file_bytes)) as probe:
            detected_format = (probe.format or "").upper()
            width, height = probe.size
    except (
        OSError,
        EOFError,
        SyntaxError,
        ValueError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
    ):
        return _validate_ela_upload(file_bytes, max_pixels)
    if detected_format != "JPEG":
        raise ELAUnsupportedFormatError("Error Level Analysis is available for JPEG images only.")
    if width * height > max_pixels:
        raise ELAError(f"ELA is limited to {max_pixels:,} pixels to bound memory use.")
    validated = _validate_ela_upload(file_bytes, max_pixels)
    pixel_count = validated.width * validated.height

    try:
        with Image.open(BytesIO(file_bytes)) as opened:
            opened.load()
            original = apply_exif_orientation(opened).convert("RGB")

        recompressed_bytes = BytesIO()
        original.save(recompressed_bytes, format="JPEG", quality=quality)
        with Image.open(BytesIO(recompressed_bytes.getvalue())) as recompressed:
            recompressed.load()
            decoded_recompressed = recompressed.convert("RGB")

        difference = ImageChops.difference(original, decoded_recompressed)
        statistics = ImageStat.Stat(difference)
        mean_difference = sum(statistics.mean) / len(statistics.mean)
        maximum_difference = max(channel_max for _, channel_max in statistics.extrema)
        changed_mask = ImageChops.lighter(
            difference.getchannel("R"),
            ImageChops.lighter(difference.getchannel("G"), difference.getchannel("B")),
        ).point(lambda value: 255 if value else 0)
        changed_histogram = changed_mask.histogram()
        changed_pixel_percent = (changed_histogram[255] / pixel_count) * 100

        display_residual = ImageEnhance.Brightness(difference).enhance(error_scale)
        residual_png = BytesIO()
        display_residual.save(residual_png, format="PNG", optimize=False)
    except (OSError, EOFError, SyntaxError, ValueError, UnidentifiedImageError) as exc:
        raise ELAError("ELA could not decode or recompress this JPEG safely.") from exc

    return ELAResult(
        width=original.width,
        height=original.height,
        quality=quality,
        error_scale=error_scale,
        mean_absolute_difference=mean_difference,
        maximum_channel_difference=maximum_difference,
        changed_pixel_percent=changed_pixel_percent,
        residual_png=residual_png.getvalue(),
        method=(
            f"Decoded RGB pixels (EXIF orientation applied) were recompressed once as JPEG at quality {quality}; "
            f"the absolute RGB difference was amplified by ×{error_scale}."
        ),
        limitations=(
            "Recompression residuals can vary with the encoder, quality, image content, and prior processing. "
            "ELA patterns are descriptive indicators and are not proof that an image was edited or manipulated."
        ),
    )


def _validate_ela_upload(file_bytes: bytes, max_pixels: int) -> ValidatedImage:
    """Run the full safe decoder after format and ELA-limit checks."""
    try:
        return validate_image_bytes(
            file_bytes,
            "ela-input.jpg",
            max_image_pixels=max_pixels,
            max_total_frame_pixels=max_pixels,
            max_frame_count=1,
        )
    except ImageValidationError as exc:
        if "pixel-count" in str(exc) or "total decoded-pixel" in str(exc):
            raise ELAError(f"ELA is limited to {max_pixels:,} pixels to bound memory use.") from exc
        raise
