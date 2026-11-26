from io import BytesIO

from PIL import Image
import pytest

import core.histogram as histogram_module
from core.histogram import HistogramError, calculate_rgb_histogram


def image_bytes(image: Image.Image, image_format: str = "PNG") -> bytes:
    output = BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


def test_histogram_counts_each_rgb_channel_and_pooled_distribution():
    image = Image.new("RGB", (2, 2))
    image.putdata([(10, 20, 30), (10, 20, 30), (40, 50, 60), (70, 80, 90)])

    result = calculate_rgb_histogram(image_bytes(image))

    assert result.pixel_count == 4
    assert sum(result.red) == sum(result.green) == sum(result.blue) == 4
    assert result.red[10] == 2
    assert result.green[20] == 2
    assert result.blue[30] == 2
    assert sum(result.combined) == 12
    assert result.combined[10] == 2
    assert result.combined[20] == 2
    assert result.combined[30] == 2
    assert "not authenticity tests" in result.limitations


def test_histogram_counts_transparency_as_decoded_rgb_without_alpha_weighting():
    image = Image.new("RGBA", (2, 1))
    image.putdata([(12, 34, 56, 0), (12, 34, 56, 255)])

    result = calculate_rgb_histogram(image_bytes(image))

    assert result.pixel_count == 2
    assert result.red[12] == 2
    assert result.green[34] == 2
    assert result.blue[56] == 2
    assert "Transparency is discarded" in result.limitations


def test_histogram_pools_all_frames_of_animated_gif():
    first = Image.new("RGB", (2, 2), "red")
    second = Image.new("RGB", (2, 2), "blue")
    output = BytesIO()
    first.save(output, format="GIF", save_all=True, append_images=[second], duration=100, loop=0)

    result = calculate_rgb_histogram(output.getvalue(), "animated.gif")

    assert result.frame_count == 2
    assert result.pixel_count == 8
    assert result.red[255] == 4
    assert result.blue[255] == 4
    assert sum(result.combined) == 24


def make_tiff_pages(first_size=(2, 2), second_size=(3, 1)) -> bytes:
    first = Image.new("RGB", first_size, (12, 34, 56))
    second = Image.new("RGB", second_size, (78, 90, 123))
    output = BytesIO()
    first.save(output, format="TIFF", save_all=True, append_images=[second])
    return output.getvalue()


def test_histogram_counts_actual_pixels_across_differently_sized_tiff_pages():
    result = calculate_rgb_histogram(make_tiff_pages(), "multipage.tif")

    assert result.frame_count == 2
    assert result.frame_dimensions == ((2, 2), (3, 1))
    assert result.pixel_count == 7
    assert sum(result.red) == sum(result.green) == sum(result.blue) == 7
    assert result.red[12] == 4
    assert result.red[78] == 3
    assert result.blue[56] == 4
    assert result.blue[123] == 3
    assert sum(result.combined) == 21


def test_oversized_later_tiff_page_is_rejected_before_histogram_processing(monkeypatch):
    original_validator = histogram_module.validate_image_bytes

    def limited_validator(file_bytes, filename):
        return original_validator(
            file_bytes,
            filename,
            max_image_pixels=16,
            max_total_frame_pixels=64,
        )

    def fail_if_histogram_crop_runs(*_args, **_kwargs):
        pytest.fail("Histogram tiles must not be processed for a resource-limit violation")

    monkeypatch.setattr(histogram_module, "validate_image_bytes", limited_validator)
    monkeypatch.setattr(Image.Image, "crop", fail_if_histogram_crop_runs)

    with pytest.raises(HistogramError, match="pixel-count safety limit"):
        calculate_rgb_histogram(make_tiff_pages((2, 2), (5, 4)), "oversized-later-page.tif")


def test_differently_sized_tiff_pages_cannot_bypass_total_frame_pixel_limit(monkeypatch):
    original_validator = histogram_module.validate_image_bytes

    def limited_validator(file_bytes, filename):
        return original_validator(
            file_bytes,
            filename,
            max_image_pixels=16,
            max_total_frame_pixels=12,
        )

    monkeypatch.setattr(histogram_module, "validate_image_bytes", limited_validator)

    with pytest.raises(HistogramError, match="total decoded-pixel limit"):
        calculate_rgb_histogram(make_tiff_pages((2, 2), (3, 3)), "over-total-pages.tif")


@pytest.mark.parametrize("file_bytes", [b"", b"not an image"])
def test_histogram_rejects_invalid_input(file_bytes):
    with pytest.raises(HistogramError):
        calculate_rgb_histogram(file_bytes)
