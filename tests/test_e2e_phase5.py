"""Phase 5 end-to-end integration, cross-platform, privacy, and resource-limit tests."""

from __future__ import annotations

from fractions import Fraction
from io import BytesIO

import pytest
from PIL import Image

from core.analysis import inspect_image
from core.assessment_engine import assess_inspection
from core.assessment_models import AssessmentOutcome
from core.comparison import compare_images
from core.ela import ELAUnsupportedFormatError, calculate_ela
from core.gps import extract_gps
from core.histogram import calculate_rgb_histogram
from core.models import MetadataStatus
from core.report import ReportOptions, generate_pdf_report, sanitize_display_filename
from utils.validators import ImageValidationError, MAX_UPLOAD_BYTES


def _encode_image(fmt: str, size: tuple[int, int] = (32, 24), *, exif: Image.Exif | None = None) -> bytes:
    buf = BytesIO()
    img = Image.new("RGB", size, color=(90, 140, 180))
    save_kwargs: dict[str, object] = {"format": fmt}
    if exif is not None:
        save_kwargs["exif"] = exif
    img.save(buf, **save_kwargs)
    return buf.getvalue()


@pytest.mark.parametrize(
    ("fmt", "ext"),
    [
        ("JPEG", "jpg"),
        ("PNG", "png"),
        ("WEBP", "webp"),
        ("TIFF", "tiff"),
        ("BMP", "bmp"),
        ("GIF", "gif"),
    ],
)
def test_e2e_all_supported_formats_pipeline(fmt: str, ext: str):
    raw = _encode_image(fmt)
    inspection = inspect_image(raw, f"sample.{ext}")
    assert inspection.properties.image_format == fmt

    assessment = assess_inspection(inspection)
    assert assessment.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE

    histogram = calculate_rgb_histogram(raw, f"sample.{ext}")
    assert histogram.pixel_count == 32 * 24

    ela_result = None
    if fmt == "JPEG":
        ela_result = calculate_ela(raw, quality=90, error_scale=10)
        assert ela_result.residual_png.startswith(b"\x89PNG")
    else:
        with pytest.raises(ELAUnsupportedFormatError):
            calculate_ela(raw)

    report = generate_pdf_report(
        inspection,
        assessment=assessment,
        options=ReportOptions(
            include_ela=ela_result is not None,
            include_histogram=True,
        ),
        ela_result=ela_result,
        histogram_result=histogram,
    )
    assert report.pdf_bytes.startswith(b"%PDF-")
    assert report.gps_included is False


def test_e2e_extension_mismatch_uses_detected_format_safely():
    png_bytes = _encode_image("PNG")
    inspection = inspect_image(png_bytes, "disguised.jpg")
    assert inspection.properties.image_format == "PNG"
    assert inspection.properties.extension_mismatch is True
    assert inspection.warnings

    with pytest.raises(ELAUnsupportedFormatError):
        calculate_ela(png_bytes)

    report = generate_pdf_report(inspection)
    assert report.pdf_bytes.startswith(b"%PDF-")


@pytest.mark.parametrize(
    ("raw_path", "expected_basename"),
    [
        ("/Users/alice/Desktop/evidence/photo.jpg", "photo.jpg"),
        (r"C:\Users\alice\Documents\evidence\photo.jpg", "photo.jpg"),
        (r"\\fileserver\share\case01\photo.jpg", "photo.jpg"),
    ],
)
def test_e2e_cross_platform_path_redaction(raw_path: str, expected_basename: str):
    assert sanitize_display_filename(raw_path, redact_paths=True) == expected_basename
    raw = _encode_image("JPEG")
    inspection = inspect_image(raw, raw_path)
    report = generate_pdf_report(inspection)
    assert report.display_filename == expected_basename
    assert report.paths_redacted is True


def test_e2e_gps_privacy_default_and_explicit_opt_in():
    exif = Image.Exif()
    exif[271] = "Canon"
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
    }
    jpeg_bytes = _encode_image("JPEG", exif=exif)
    inspection = inspect_image(jpeg_bytes, "location.jpg")
    assessment = assess_inspection(inspection)
    assert assessment.outcome is AssessmentOutcome.LOW_CONCERN

    # Normal inspection metadata does not expose GPS coordinates
    assert not any("37.808" in (f.value or "") for f in inspection.metadata)

    gps = extract_gps(jpeg_bytes, "JPEG")
    assert gps.status is MetadataStatus.PRESENT

    default_report = generate_pdf_report(inspection, assessment=assessment, gps_result=gps)
    assert default_report.gps_included is False
    assert "GPS Information" not in default_report.included_sections

    opted_in_report = generate_pdf_report(
        inspection,
        assessment=assessment,
        gps_result=gps,
        options=ReportOptions(include_gps=True),
    )
    assert opted_in_report.gps_included is True
    assert "GPS Information" in opted_in_report.included_sections


def test_e2e_resource_limits_enforced():
    with pytest.raises(ImageValidationError):
        inspect_image(b"x" * (MAX_UPLOAD_BYTES + 1), "oversized.jpg")

    with pytest.raises(ImageValidationError):
        inspect_image(b"", "empty.jpg")


def test_e2e_comparison_and_assessment_integration():
    exif = Image.Exif()
    exif[271] = "Canon"
    img_a = _encode_image("JPEG", (32, 24), exif=exif)
    img_b = _encode_image("PNG", (32, 24))
    comp = compare_images(img_a, "a.jpg", img_b, "b.png")
    assert comp.reference.sha256 != comp.suspect.sha256
    assert comp.sampled_pixel_similarity is not None
