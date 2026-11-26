from io import BytesIO

from PIL import Image

from core.analysis import inspect_image


def test_inspection_uses_uploaded_bytes_and_returns_phase_one_results():
    image = Image.new("RGB", (9, 7), (12, 34, 56))
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    original = buffer.getvalue()

    result = inspect_image(original, "photo.png")

    assert result.properties.image_format == "PNG"
    assert result.properties.file_size_bytes == len(original)
    assert len(result.sha256) == 64
    assert result.warnings == ()


def test_inspection_warns_on_mismatched_extension():
    image = Image.new("RGB", (9, 7), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    result = inspect_image(buffer.getvalue(), "photo.jpg")
    assert result.warnings
    assert "detected image format" in result.warnings[0]
