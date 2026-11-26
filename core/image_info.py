"""Image-property extraction built on validated, content-detected images."""

from pathlib import PurePosixPath

from core.models import ImageProperties
from utils.validators import FORMAT_MIME_TYPES, ValidatedImage, validate_image_bytes


def extract_image_properties(
    file_bytes: bytes,
    filename: str,
    *,
    validated: ValidatedImage | None = None,
) -> ImageProperties:
    """Return properties derived from decoded image content and original bytes."""
    if validated is None:
        validated = validate_image_bytes(file_bytes, filename)
    safe_name = PurePosixPath((filename or "upload").replace("\\", "/")).name or "upload"
    ratio = validated.width / validated.height
    megapixels = (validated.width * validated.height) / 1_000_000
    return ImageProperties(
        filename=safe_name,
        file_size_bytes=len(file_bytes),
        image_format=validated.image_format,
        mime_type=FORMAT_MIME_TYPES[validated.image_format],
        width=validated.width,
        height=validated.height,
        aspect_ratio=ratio,
        megapixels=megapixels,
        color_mode=validated.color_mode,
        bit_depth_per_channel=validated.bit_depth_per_channel,
        frame_count=validated.frame_count,
        has_transparency=validated.has_transparency,
        extension_mismatch=validated.extension_mismatch,
    )
