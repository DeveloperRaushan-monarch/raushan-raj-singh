"""Tests for Phase 4 monochrome A4 PDF forensic report generation."""

from __future__ import annotations

import base64
import re
import zlib

from core.assessment_engine import BOUNDARY_STATEMENT, assess_inspection
from core.assessment_models import AssessmentOutcome
from core.ela import ELAResult
from core.gps import GPSResult
from core.histogram import HistogramResult
from core.models import ImageInspection, ImageProperties, MetadataField, MetadataStatus
from core.report import ReportOptions, generate_pdf_report, sanitize_display_filename


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decode ASCII85/FlateDecode PDF content streams and extract literal strings."""
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        raw = match.group(1).strip()
        try:
            if raw.endswith(b"~>"):
                raw = base64.a85decode(raw, adobe=True)
            decoded = zlib.decompress(raw)
        except (ValueError, zlib.error):
            decoded = raw
        text = decoded.decode("latin-1", errors="ignore")
        literals = re.findall(r"\((.*?)\)\s*Tj|\[(.*?)\]\s*TJ", text, re.DOTALL)
        for tj, tj_array in literals:
            if tj:
                chunks.append(tj)
            if tj_array:
                chunks.extend(re.findall(r"\((.*?)\)", tj_array))
    joined = " ".join(chunks)
    return joined.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")


def _sample_inspection(
    *,
    filename: str = "sample.jpg",
    fields: tuple[MetadataField, ...] = (),
) -> ImageInspection:
    return ImageInspection(
        properties=ImageProperties(
            filename=filename,
            file_size_bytes=4096,
            image_format="JPEG",
            mime_type="image/jpeg",
            width=100,
            height=80,
            aspect_ratio=1.25,
            megapixels=0.008,
            color_mode="RGB",
            bit_depth_per_channel=8,
            frame_count=1,
            has_transparency=False,
            extension_mismatch=False,
        ),
        metadata=fields,
        sha256="ab" * 32,
    )


def test_pdf_report_contains_required_sections_and_disclaimers():
    inspection = _sample_inspection(
        fields=(
            MetadataField("make", "Camera make", "Canon", MetadataStatus.PRESENT, "EXIF"),
            MetadataField("orientation", "Orientation", "9", MetadataStatus.INVALID, "EXIF"),
            MetadataField("xmp", "XMP packet", None, MetadataStatus.UNSUPPORTED, "XMP"),
        )
    )
    assessment = assess_inspection(inspection)
    assert assessment.outcome is AssessmentOutcome.NEEDS_REVIEW

    report = generate_pdf_report(
        inspection,
        assessment=assessment,
        report_id="PT-RPT-TEST0001",
        generated_at_utc="2026-11-25 18:00:00 UTC",
    )
    assert report.pdf_bytes.startswith(b"%PDF-")
    text = _extract_pdf_text(report.pdf_bytes)
    assert "PT-RPT-TEST0001" in text
    assert "2026-11-25 18:00:00 UTC" in text
    assert "NEEDS REVIEW" in text
    assert "invalid-metadata-orientation" in text
    assert "ab" * 32 in text
    assert BOUNDARY_STATEMENT[:40] in text
    assert not re.search(r"\b(REAL|FAKE)\b", text)


def test_gps_excluded_by_default_even_when_gps_result_provided():
    inspection = _sample_inspection(
        fields=(MetadataField("make", "Camera make", "Canon", MetadataStatus.PRESENT, "EXIF"),)
    )
    gps = GPSResult(
        status=MetadataStatus.PRESENT,
        latitude=37.808333,
        longitude=-122.404167,
        altitude_meters=15.0,
        timestamp_utc="2026:11:25 10:00:00",
    )
    report = generate_pdf_report(inspection, gps_result=gps)
    assert report.gps_included is False
    text = _extract_pdf_text(report.pdf_bytes)
    assert "Excluded by default" in text
    assert "37.808333" not in text
    assert "-122.404167" not in text


def test_gps_included_only_when_explicitly_enabled_and_present():
    inspection = _sample_inspection(
        fields=(MetadataField("make", "Camera make", "Canon", MetadataStatus.PRESENT, "EXIF"),)
    )
    gps = GPSResult(
        status=MetadataStatus.PRESENT,
        latitude=37.808333,
        longitude=-122.404167,
    )
    report = generate_pdf_report(
        inspection,
        gps_result=gps,
        options=ReportOptions(include_gps=True),
    )
    assert report.gps_included is True
    text = _extract_pdf_text(report.pdf_bytes)
    assert "37.808333" in text
    assert "-122.404167" in text


def test_gps_enabled_with_missing_or_unavailable_gps_does_not_crash():
    inspection = _sample_inspection()
    gps = GPSResult(status=MetadataStatus.UNAVAILABLE, note="GPS unavailable.")
    report = generate_pdf_report(
        inspection,
        gps_result=gps,
        options=ReportOptions(include_gps=True),
    )
    assert report.gps_included is False
    assert report.pdf_bytes.startswith(b"%PDF-")


def test_macos_and_windows_paths_are_redacted_by_default():
    assert sanitize_display_filename("/Users/alice/Desktop/secret/photo.jpg") == "photo.jpg"
    assert sanitize_display_filename(r"C:\Users\alice\Pictures\photo.jpg") == "photo.jpg"

    inspection = _sample_inspection(filename=r"C:\Users\alice\PrivateFolder\evidence.jpg")
    report = generate_pdf_report(inspection)
    assert report.display_filename == "evidence.jpg"
    text = _extract_pdf_text(report.pdf_bytes)
    assert "evidence.jpg" in text
    assert "PrivateFolder" not in text


def test_optional_ela_and_histogram_sections_respect_selection_and_availability():
    inspection = _sample_inspection()
    ela = ELAResult(
        width=100,
        height=80,
        quality=90,
        error_scale=10,
        mean_absolute_difference=1.25,
        maximum_channel_difference=14,
        changed_pixel_percent=12.5,
        residual_png=b"png",
        method="One-pass JPEG recompression.",
        limitations="ELA is descriptive only.",
    )
    hist = HistogramResult(
        width=100,
        height=80,
        frame_count=1,
        frame_dimensions=((100, 80),),
        pixel_count=8000,
        red=(0,) * 256,
        green=(0,) * 256,
        blue=(0,) * 256,
        combined=(0,) * 256,
        method="256-bin RGB histogram.",
        limitations="Histograms are descriptive only.",
    )

    excluded = generate_pdf_report(
        inspection,
        ela_result=ela,
        histogram_result=hist,
        options=ReportOptions(include_ela=False, include_histogram=False),
    )
    assert "Error Level Analysis" not in excluded.included_sections
    assert "RGB Histogram" not in excluded.included_sections

    included = generate_pdf_report(
        inspection,
        ela_result=ela,
        histogram_result=hist,
        options=ReportOptions(include_ela=True, include_histogram=True),
    )
    assert "Error Level Analysis" in included.included_sections
    assert "RGB Histogram" in included.included_sections
    text = _extract_pdf_text(included.pdf_bytes)
    assert "1.250" in text
    assert "8,000" in text


def test_long_metadata_values_and_many_fields_produce_multipage_pdf():
    long_fields = tuple(
        MetadataField(
            f"field_{i}",
            f"Custom Field {i}",
            f"<Value & Tag {i}> " + ("X" * 180),
            MetadataStatus.PRESENT,
            "XMP",
            "Long note " + ("Y" * 80),
        )
        for i in range(45)
    )
    inspection = _sample_inspection(fields=long_fields)
    report = generate_pdf_report(inspection)
    assert report.pdf_bytes.startswith(b"%PDF-")
    assert report.pdf_bytes.count(b"/Type /Page\n") >= 2 or report.pdf_bytes.count(b"/Type /Page ") >= 2


def test_app_forensic_reports_tab_defaults_and_generation():
    from io import BytesIO
    from pathlib import Path
    from PIL import Image
    from streamlit.testing.v1 import AppTest

    buffer = BytesIO()
    exif = Image.Exif()
    exif[271] = "Canon"
    Image.new("RGB", (24, 16), color=(100, 120, 140)).save(buffer, format="JPEG", exif=exif)

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=8).run(timeout=8)
    app.file_uploader[0].set_value(("canon.jpg", buffer.getvalue(), "image/jpeg"))
    app.run(timeout=8)
    assert not app.exception

    report_tab = app.tabs[7]
    assert report_tab.label == "Forensic Reports"
    assert any("excluded from the report by default" in item.value for item in report_tab.info)

    generate_btn = next(b for b in report_tab.button if b.label == "Generate PDF report")
    generate_btn.click()
    app.run(timeout=8)
    assert not app.exception
    assert "pixeltruth_report_result" in app.session_state
    assert app.session_state["pixeltruth_report_result"].pdf_bytes.startswith(b"%PDF-")


def test_app_report_preview_escapes_html_special_characters():
    from io import BytesIO
    from pathlib import Path
    from PIL import Image
    from streamlit.testing.v1 import AppTest

    buffer = BytesIO()
    Image.new("RGB", (24, 16), color=(100, 120, 140)).save(buffer, format="PNG")

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=8).run(timeout=8)
    app.file_uploader[0].set_value(("<img src=x>.png", buffer.getvalue(), "image/png"))
    app.run(timeout=8)
    assert not app.exception

    report_tab = app.tabs[7]
    preview_markup = " ".join(item.value for item in report_tab.markdown)
    assert "&lt;img src=x&gt;.png" in preview_markup
    assert "<code><img" not in preview_markup


def test_pdf_malware_section_excluded_by_default_and_backward_compatible():
    insp = _sample_inspection()
    assess = assess_inspection(insp)
    res_default = generate_pdf_report(insp, assessment=assess)
    assert "Malware & Security Analysis" not in res_default.included_sections
    text = _extract_pdf_text(res_default.pdf_bytes)
    assert "Malware and Security Analysis" not in text


def test_pdf_malware_section_all_states_and_missing_result():
    from core.malware_models import (
        DatabaseFreshnessStatus,
        MalwareDetection,
        MalwareScanOutcome,
        MalwareScanResult,
    )

    insp = _sample_inspection(filename="/Users/private/secret_dir/photo.jpg")
    assess = assess_inspection(insp)
    opts = ReportOptions(include_malware_scan=True, redact_local_paths=True)

    # 1. NO_KNOWN_THREAT
    clean = MalwareScanResult(
        file_hash_sha256=insp.sha256,
        scanner_name="ClamAV",
        scanner_version="1.5.5",
        signature_database_version="28194",
        database_freshness=DatabaseFreshnessStatus.CURRENT,
        scan_status=MalwareScanOutcome.NO_KNOWN_THREAT,
        detection_count=0,
    )
    r_clean = generate_pdf_report(insp, assessment=assess, options=opts, malware_scan=clean)
    assert "Malware & Security Analysis" in r_clean.included_sections
    t_clean = _extract_pdf_text(r_clean.pdf_bytes)
    assert "NO_KNOWN_THREAT" in t_clean
    assert "does not guarantee that the file is completely safe" in t_clean
    assert "/Users/private" not in t_clean

    # 2. MALWARE_DETECTED (multiple detections)
    infected = MalwareScanResult(
        file_hash_sha256=insp.sha256,
        scanner_name="ClamAV",
        scanner_version="1.5.5",
        signature_database_version="28194",
        database_freshness=DatabaseFreshnessStatus.CURRENT,
        scan_status=MalwareScanOutcome.MALWARE_DETECTED,
        detection_count=2,
        detections=(
            MalwareDetection(detection_name="Eicar-Signature", threat_category="Test Signature"),
            MalwareDetection(detection_name="Win.Trojan.Alpha-1", threat_category="Trojan"),
        ),
    )
    r_inf = generate_pdf_report(insp, assessment=assess, options=opts, malware_scan=infected)
    t_inf = _extract_pdf_text(r_inf.pdf_bytes)
    assert "Eicar-Signature" in t_inf
    assert "Win.Trojan.Alpha-1" in t_inf
    assert "2" in t_inf
    # PT-EA/1.0.0 assessment remains unchanged
    assert r_inf.rule_set_version == assess.rule_set_version

    # 3. SCAN_INCOMPLETE
    inc = MalwareScanResult(
        file_hash_sha256=insp.sha256,
        scan_status=MalwareScanOutcome.SCAN_INCOMPLETE,
        reason_code="DATABASE_OUTDATED",
        warnings=("Database is outdated.",),
        limitations=("Scan could not verify recent signatures.",),
    )
    r_inc = generate_pdf_report(insp, assessment=assess, options=opts, malware_scan=inc)
    t_inc = _extract_pdf_text(r_inc.pdf_bytes)
    assert "SCAN_INCOMPLETE" in t_inc
    assert "DATABASE_OUTDATED" in t_inc

    # 4. Missing malware result
    r_none = generate_pdf_report(insp, assessment=assess, options=opts, malware_scan=None)
    assert "Malware & Security Analysis" in r_none.included_sections
    assert "unknown" in _extract_pdf_text(r_none.pdf_bytes).lower()
