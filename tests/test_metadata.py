from io import BytesIO

from PIL import Image

from core.metadata import extract_metadata
from core.models import MetadataStatus


def make_jpeg(exif=None):
    image = Image.new("RGB", (16, 12), "white")
    output = BytesIO()
    image.save(output, format="JPEG", exif=exif or b"")
    return output.getvalue()


def test_missing_exif_fields_have_missing_status():
    fields = extract_metadata(make_jpeg(), "JPEG")
    make = next(field for field in fields if field.key == "make")
    assert make.status is MetadataStatus.MISSING
    assert make.value is None


def test_extracts_present_camera_fields():
    exif = Image.Exif()
    exif[271] = "PIXELTRUTH TEST CAMERA"
    exif[272] = "Model 1"
    fields = extract_metadata(make_jpeg(exif), "JPEG")
    by_key = {field.key: field for field in fields}
    assert by_key["make"].status is MetadataStatus.PRESENT
    assert by_key["make"].value == "PIXELTRUTH TEST CAMERA"
    assert by_key["model"].value == "Model 1"


def test_marks_out_of_range_orientation_invalid():
    exif = Image.Exif()
    exif[274] = 9
    fields = extract_metadata(make_jpeg(exif), "JPEG")
    orientation = next(field for field in fields if field.key == "orientation")
    assert orientation.status is MetadataStatus.INVALID


def test_accepts_exifread_orientation_labels_for_valid_values():
    for orientation_value in (1, 6):
        exif = Image.Exif()
        exif[274] = orientation_value
        fields = extract_metadata(make_jpeg(exif), "JPEG")
        orientation = next(field for field in fields if field.key == "orientation")
        assert orientation.status is MetadataStatus.PRESENT


def test_non_exif_format_marks_fields_unsupported():
    fields = extract_metadata(b"unused bytes", "BMP")
    make = next(field for field in fields if field.key == "make")
    assert make.status is MetadataStatus.UNSUPPORTED


def test_xmp_and_iptc_are_reported_as_unsupported_in_phase_one():
    fields = extract_metadata(make_jpeg(), "JPEG")
    by_key = {field.key: field for field in fields}
    assert by_key["xmp"].status is MetadataStatus.UNSUPPORTED
    assert by_key["iptc"].status is MetadataStatus.UNSUPPORTED
