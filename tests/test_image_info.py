from io import BytesIO

from PIL import Image

from core.image_info import extract_image_properties


def test_extracts_properties_and_sanitizes_filename():
    image = Image.new("RGBA", (40, 20), (10, 20, 30, 100))
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    result = extract_image_properties(buffer.getvalue(), r"C:\users\private\sample.png")

    assert result.filename == "sample.png"
    assert result.image_format == "PNG"
    assert result.mime_type == "image/png"
    assert (result.width, result.height) == (40, 20)
    assert result.aspect_ratio == 2.0
    assert result.megapixels == 0.0008
    assert result.color_mode == "RGBA"
    assert result.has_transparency is True
    assert result.extension_mismatch is False


def test_reports_extension_mismatch_without_trusting_extension():
    image = Image.new("RGB", (5, 3), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    result = extract_image_properties(buffer.getvalue(), "renamed.jpg")
    assert result.image_format == "PNG"
    assert result.mime_type == "image/png"
    assert result.extension_mismatch is True


def test_palette_image_bit_depth_is_unavailable_when_not_reliably_known():
    image = Image.new("P", (4, 4), 0)
    image.putpalette([0, 0, 0, 255, 255, 255] + [0] * 762)
    buffer = BytesIO()
    image.save(buffer, format="GIF")

    result = extract_image_properties(buffer.getvalue(), "palette.gif")
    assert result.color_mode == "P"
    assert result.bit_depth_per_channel is None
