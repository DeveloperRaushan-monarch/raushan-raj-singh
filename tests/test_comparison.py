from io import BytesIO

from PIL import Image

from core.comparison import compare_images


def make_image(size, color, image_format="PNG"):
    output = BytesIO()
    Image.new("RGB", size, color).save(output, format=image_format)
    return output.getvalue()


def test_identical_files_match_hash_and_pixel_indicator():
    data = make_image((12, 8), (12, 34, 56))
    result = compare_images(data, "a.png", data, "b.png")
    assert result.hashes_match is True
    assert result.sampled_pixel_similarity == 1.0
    assert result.metadata_differences == ()


def test_different_dimensions_do_not_receive_pixel_similarity_score():
    reference = make_image((12, 8), "black")
    suspect = make_image((10, 8), "black")
    result = compare_images(reference, "a.png", suspect, "b.png")
    assert result.hashes_match is False
    assert result.sampled_pixel_similarity is None
    assert "dimensions differ" in result.similarity_note


def test_comparison_reports_metadata_values_that_differ():
    reference_exif = Image.Exif()
    reference_exif[271] = "Camera A"
    suspect_exif = Image.Exif()
    suspect_exif[271] = "Camera B"
    a = BytesIO()
    b = BytesIO()
    Image.new("RGB", (8, 8), "white").save(a, format="JPEG", exif=reference_exif)
    Image.new("RGB", (8, 8), "white").save(b, format="JPEG", exif=suspect_exif)
    result = compare_images(a.getvalue(), "a.jpg", b.getvalue(), "b.jpg")
    make = next(item for item in result.metadata_differences if item.label == "Camera make")
    assert make.reference_value.endswith("Camera A")
    assert make.suspect_value.endswith("Camera B")
