from io import BytesIO

import pytest
from PIL import Image

from utils.validators import ImageValidationError, validate_image_bytes


def make_image_bytes(image_format: str) -> bytes:
    image = Image.new("RGBA" if image_format in {"PNG", "WEBP", "GIF"} else "RGB", (8, 6), (10, 20, 30, 100) if image_format in {"PNG", "WEBP", "GIF"} else (10, 20, 30))
    output = BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


@pytest.mark.parametrize(
    ("image_format", "filename"),
    [
        ("JPEG", "photo.jpg"),
        ("PNG", "photo.png"),
        ("WEBP", "photo.webp"),
        ("TIFF", "photo.tiff"),
        ("BMP", "photo.bmp"),
        ("GIF", "photo.gif"),
    ],
)
def test_detects_and_decodes_supported_formats(image_format, filename):
    result = validate_image_bytes(make_image_bytes(image_format), filename)
    assert result.image_format == image_format
    assert (result.width, result.height) == (8, 6)
    assert result.frame_count == 1


def test_rejects_non_image_bytes():
    with pytest.raises(ImageValidationError, match="not a supported"):
        validate_image_bytes(b"not an image", "photo.jpg")


def test_rejects_empty_upload():
    with pytest.raises(ImageValidationError, match="empty"):
        validate_image_bytes(b"", "photo.jpg")


def test_rejects_upload_over_byte_limit():
    image_bytes = make_image_bytes("PNG")
    with pytest.raises(ImageValidationError, match="upload limit"):
        validate_image_bytes(image_bytes, "photo.png", max_upload_bytes=len(image_bytes) - 1)


def test_rejects_content_over_pixel_limit():
    with pytest.raises(ImageValidationError, match="pixel-count"):
        validate_image_bytes(make_image_bytes("PNG"), "photo.png", max_image_pixels=10)


def test_detects_extension_mismatch_from_content():
    result = validate_image_bytes(make_image_bytes("PNG"), "disguised.jpg")
    assert result.image_format == "PNG"
    assert result.extension_mismatch is True


def test_strips_client_path_from_filename():
    result = validate_image_bytes(make_image_bytes("PNG"), r"C:\private\photo.png")
    assert result.image_format == "PNG"
