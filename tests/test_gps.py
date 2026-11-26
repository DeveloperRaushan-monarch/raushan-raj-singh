from fractions import Fraction
from io import BytesIO

import pytest
from PIL import Image

from core.analysis import inspect_image
from core.gps import extract_gps
from core.models import MetadataStatus


def make_image_with_gps(image_format="JPEG"):
    exif = Image.Exif()
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
        6: Fraction(12),
        7: (Fraction(10), Fraction(20), Fraction(30)),
        29: "2024:01:02",
    }
    output = BytesIO()
    exif_value = exif.tobytes() if image_format == "TIFF" else exif
    Image.new("RGB", (8, 8), "white").save(output, format=image_format, exif=exif_value)
    return output.getvalue()


@pytest.mark.parametrize("image_format", ["JPEG", "PNG", "WEBP", "TIFF"])
def test_gps_is_extracted_only_through_explicit_gps_function(image_format):
    result = extract_gps(make_image_with_gps(image_format), image_format)
    assert result.status is MetadataStatus.PRESENT
    assert abs(result.latitude - 37.8083333333) < 1e-8
    assert abs(result.longitude - (-122.4041666667)) < 1e-8
    assert result.altitude_meters == 12
    assert result.timestamp_utc == "2024-01-02 10:20:30 UTC"


def test_absent_gps_returns_missing_without_coordinates():
    output = BytesIO()
    Image.new("RGB", (8, 8), "white").save(output, format="JPEG")
    result = extract_gps(output.getvalue())
    assert result.status is MetadataStatus.MISSING
    assert result.latitude is None
    assert result.longitude is None


def test_regular_inspection_does_not_expose_gps_fields():
    file_bytes = make_image_with_gps()
    result = inspect_image(file_bytes, "location.jpg")
    assert not any("gps" in field.key.lower() for field in result.metadata)
    assert not any("37.8" in finding.observed_evidence for finding in result.findings)
