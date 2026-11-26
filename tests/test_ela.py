from io import BytesIO

from PIL import Image, ImageChops, ImageEnhance, ImageStat
import pytest

from core.ela import ELAError, ELAUnsupportedFormatError, apply_exif_orientation, calculate_ela
from utils.validators import ImageValidationError


def make_jpeg(size=(40, 30)):
    image = Image.new("RGB", size)
    image.putdata(
        [
            ((x * 17 + y * 3) % 256, (x * 5 + y * 19) % 256, (x * 11 + y * 7) % 256)
            for y in range(size[1])
            for x in range(size[0])
        ]
    )
    output = BytesIO()
    image.save(output, format="JPEG", quality=96)
    return output.getvalue()


def make_png():
    output = BytesIO()
    Image.new("RGB", (8, 6), "white").save(output, format="PNG")
    return output.getvalue()


def make_grayscale_jpeg(size=(8, 6)):
    output = BytesIO()
    Image.new("L", size, 128).save(output, format="JPEG", quality=95)
    return output.getvalue()


def test_ela_returns_residual_and_method_parameters_for_jpeg():
    result = calculate_ela(make_jpeg(), quality=85, error_scale=8)
    with Image.open(BytesIO(result.residual_png)) as residual:
        assert residual.format == "PNG"
        assert residual.size == (40, 30)
    assert result.quality == 85
    assert result.error_scale == 8
    assert result.mean_absolute_difference > 0
    assert 0 <= result.maximum_channel_difference <= 255
    assert 0 < result.changed_pixel_percent <= 100
    assert "quality 85" in result.method
    assert "×8" in result.method
    assert "not proof" in result.limitations


def test_ela_error_scale_changes_only_display_amplification():
    image = make_jpeg()
    low = calculate_ela(image, quality=85, error_scale=1)
    high = calculate_ela(image, quality=85, error_scale=10)
    assert low.mean_absolute_difference == high.mean_absolute_difference
    assert low.maximum_channel_difference == high.maximum_channel_difference
    with Image.open(BytesIO(low.residual_png)) as low_image, Image.open(BytesIO(high.residual_png)) as high_image:
        assert sum(ImageStat.Stat(high_image).mean) >= sum(ImageStat.Stat(low_image).mean)


def test_ela_is_content_based_and_rejects_non_jpeg():
    with pytest.raises(ELAUnsupportedFormatError, match="JPEG images only"):
        calculate_ela(make_png())


def test_ela_rejects_corrupt_input_with_validation_error():
    with pytest.raises(ImageValidationError, match="not a supported"):
        calculate_ela(b"not an image")


def test_ela_enforces_pixel_limit_without_resizing():
    with pytest.raises(ELAError, match="limited to 64 pixels"):
        calculate_ela(make_jpeg((12, 8)), max_pixels=64)


def test_ela_accepts_exact_pixel_limit_boundary():
    result = calculate_ela(make_jpeg((8, 8)), max_pixels=64)
    assert (result.width, result.height) == (8, 8)


def test_ela_rejects_one_pixel_over_pixel_limit():
    with pytest.raises(ELAError, match="limited to 64 pixels"):
        calculate_ela(make_jpeg((9, 8)), max_pixels=64)


def test_ela_supports_grayscale_jpeg():
    result = calculate_ela(make_grayscale_jpeg())
    with Image.open(BytesIO(result.residual_png)) as residual:
        assert residual.mode == "RGB"
        assert residual.size == (8, 6)


@pytest.mark.parametrize("parameter", ["max_pixels", "quality", "error_scale"])
def test_ela_rejects_boolean_parameters(parameter):
    with pytest.raises(ELAError):
        calculate_ela(make_jpeg(), **{parameter: True})


def test_ela_applies_exif_orientation_to_residual():
    output = BytesIO()
    exif = Image.Exif()
    exif[274] = 6
    image = Image.new("RGB", (32, 24))
    for y in range(24):
        for x in range(32):
            if x < 16 and y < 12:
                color = (240, 20, 20)
            elif x >= 16 and y < 12:
                color = (20, 230, 20)
            elif x < 16:
                color = (20, 20, 240)
            else:
                color = (230, 220, 20)
            image.putpixel((x, y), color)
    image.save(output, format="JPEG", quality=96, exif=exif)

    jpeg_bytes = output.getvalue()
    result = calculate_ela(jpeg_bytes)
    with Image.open(BytesIO(result.residual_png)) as residual:
        assert residual.size == (24, 32)

    with Image.open(BytesIO(jpeg_bytes)) as source:
        raw_pixels = source.convert("RGB")
        original_preview = apply_exif_orientation(source.copy()).convert("RGB")
    expected_orientation = raw_pixels.transpose(Image.Transpose.ROTATE_270)
    assert original_preview.tobytes() == expected_orientation.tobytes()

    recompressed = BytesIO()
    original_preview.save(recompressed, format="JPEG", quality=90)
    with Image.open(BytesIO(recompressed.getvalue())) as decoded:
        difference = ImageChops.difference(original_preview, decoded.convert("RGB"))
        expected = ImageEnhance.Brightness(difference).enhance(result.error_scale)
    with Image.open(BytesIO(result.residual_png)) as actual:
        assert actual.tobytes() == expected.tobytes()


@pytest.mark.parametrize(
    ("quality", "error_scale"),
    [(49, 10), (101, 10), (90, 0), (90, 21)],
)
def test_ela_rejects_out_of_range_parameters(quality, error_scale):
    with pytest.raises(ELAError):
        calculate_ela(make_jpeg(), quality=quality, error_scale=error_scale)
