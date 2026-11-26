"""Comprehensive tests for universal multi-engine metadata extraction, ExifTool adapter,
format capabilities, signature identification, and multi-engine merging."""

from __future__ import annotations

from io import BytesIO
import json
import subprocess
from unittest.mock import MagicMock, patch

from PIL import Image
import pytest

from core.analysis import inspect_image
from core.exiftool_engine import discover_exiftool, run_exiftool
from core.format_capabilities import SupportLevel, get_format_capability, identify_file_signature
from core.metadata_merger import merge_metadata_records
from core.metadata_models import MetadataRecord, StageCompletionState
from core.models import MetadataStatus


def _encode(fmt: str, *, size: tuple[int, int] = (32, 24), progressive: bool = False) -> bytes:
    buf = BytesIO()
    img = Image.new("RGB", size, color=(40, 120, 200))
    kw: dict[str, object] = {"format": fmt}
    if fmt == "JPEG":
        kw["progressive"] = progressive
    img.save(buf, **kw)
    return buf.getvalue()


@pytest.mark.parametrize(
    ("header", "filename", "expected_fmt", "expected_mismatch"),
    [
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "photo.jpg", "JPEG", False),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "photo.png", "JPEG", True),
        (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "screen.png", "PNG", False),
        (b"RIFF\x10\x00\x00\x00WEBP", "anim.webp", "WEBP", False),
        (b"GIF89a\x10\x00\x10\x00\x80\x00\x00", "anim.gif", "GIF", False),
        (b"BM\x00\x00\x00\x00", "img.bmp", "BMP", False),
        (b"II*\x00\x08\x00\x00\x00", "scan.tiff", "TIFF", False),
        (b"MM\x00*\x00\x00\x00\x08", "scan.tif", "TIFF", False),
        (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00", "iphone.heic", "HEIC", False),
        (b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00", "web.avif", "AVIF", False),
        (b"\xff\x0a\x00\x00", "next.jxl", "JXL", False),
        (b"II*\x00\x10\x00\x00\x00CR\x02\x00", "raw.cr2", "RAW_CR2", False),
        (b"II*\x00\x08\x00\x00\x00", "photo.dng", "RAW_DNG", False),
        (b"FUJIFILMCCD-RAW ", "fuji.raf", "RAW_RAF", False),
    ],
)
def test_identify_file_signature_all_formats(
    header: bytes, filename: str, expected_fmt: str, expected_mismatch: bool
):
    sig = identify_file_signature(header, filename)
    assert sig.detected_format == expected_fmt
    assert sig.extension_mismatch is expected_mismatch
    assert sig.confidence == "HIGH"


def test_format_capability_registry_levels():
    assert get_format_capability("JPEG").support_level is SupportLevel.FULLY_SUPPORTED
    assert get_format_capability("PNG").support_level is SupportLevel.FULLY_SUPPORTED
    assert get_format_capability("GIF").support_level is SupportLevel.PARTIALLY_SUPPORTED
    assert get_format_capability("HEIC", exiftool_available=False, pillow_decodable=False).support_level is SupportLevel.IDENTIFIED_ONLY
    assert get_format_capability("HEIC", exiftool_available=True, pillow_decodable=False).support_level is SupportLevel.METADATA_ONLY
    raw_cap = get_format_capability("RAW_DNG", exiftool_available=True)
    assert raw_cap.support_level is SupportLevel.METADATA_ONLY
    assert raw_cap.pixel_decoding_support is False
    assert get_format_capability("UNKNOWN").support_level is SupportLevel.UNSUPPORTED


def test_exiftool_unavailable_graceful():
    with patch("core.exiftool_engine.discover_exiftool") as mock_disc:
        mock_disc.return_value.available = False
        mock_disc.return_value.executable_path = None
        mock_disc.return_value.reason = "Not installed"
        res = run_exiftool(b"\xff\xd8\xff\xe0", "a.jpg")
        assert res.execution_status == "UNAVAILABLE"
        assert res.records == ()


def test_exiftool_mocked_json_parsing_and_gps_gating(tmp_path):
    fake_exe = tmp_path / "exiftool"
    fake_exe.write_text("#!/bin/sh\n")
    payload = [
        {
            "SourceFile": "/tmp/fake.jpg",
            "IFD0:Make": {"id": 271, "val": "Canon"},
            "IFD0:Model": {"id": 272, "val": "EOS R5"},
            "GPS:GPSLatitude": "37.8083",
            "Composite:Megapixels": 45.0,
            "MakerNotes:LensID": {"id": 149, "val": "RF 24-70mm F2.8L"},
        }
    ]
    ver_proc = MagicMock(returncode=0, stdout="12.76\n", stderr="")
    run_proc = MagicMock(returncode=0, stdout=json.dumps(payload), stderr="")

    with patch("core.exiftool_engine.subprocess.run", side_effect=[ver_proc, run_proc]) as mock_run:
        res = run_exiftool(_encode("JPEG"), "canon.jpg", configured_path=str(fake_exe))
        assert mock_run.call_count == 2
        assert res.status.available is True
        assert res.status.version == "12.76"
        assert res.execution_status == "COMPLETED"
        assert res.gps_present_indicator is True
        # GPS tags must NOT leak into ordinary records
        assert all(r.group != "GPS" for r in res.records)
        make_rec = next(r for r in res.records if r.tag_name == "Make")
        assert make_rec.tag_id == "271"
        assert make_rec.raw_value == "Canon"
        assert make_rec.source_engine == "ExifTool"


def test_exiftool_timeout_and_malformed_json(tmp_path):
    fake_exe = tmp_path / "exiftool"
    fake_exe.write_text("#!/bin/sh\n")
    ver_proc = MagicMock(returncode=0, stdout="12.76\n", stderr="")

    with patch(
        "core.exiftool_engine.subprocess.run",
        side_effect=[ver_proc, subprocess.TimeoutExpired(cmd="exiftool", timeout=1.0)],
    ):
        res = run_exiftool(b"\xff\xd8\xff\xe0", "t.jpg", configured_path=str(fake_exe), timeout_seconds=1.0)
        assert res.execution_status == "TIMEOUT"
        assert res.error is not None

    bad_proc = MagicMock(returncode=0, stdout="{not valid json", stderr="")
    with patch("core.exiftool_engine.subprocess.run", side_effect=[ver_proc, bad_proc]):
        res2 = run_exiftool(b"\xff\xd8\xff\xe0", "b.jpg", configured_path=str(fake_exe))
        assert res2.execution_status == "FAILED"
        assert "Malformed JSON" in (res2.error or "")


def test_multi_engine_merging_dedup_and_disagreement():
    r_int = MetadataRecord(
        record_id="exif:Make",
        source="EXIF",
        category="EXIF Metadata",
        tag_name="Make",
        raw_value="Canon",
        interpreted_value="Canon",
        source_engine="exifread",
    )
    r_et_match = MetadataRecord(
        record_id="exiftool:IFD0:Make:0",
        source="ExifTool",
        category="EXIF Metadata",
        tag_name="Make",
        tag_id="0x010F",
        namespace="IFD0",
        raw_value="Canon",
        interpreted_value="Canon",
        source_engine="ExifTool",
    )
    r_et_conflict = MetadataRecord(
        record_id="exiftool:IFD0:Make:0",
        source="ExifTool",
        category="EXIF Metadata",
        tag_name="Make",
        namespace="IFD0",
        raw_value="Nikon",
        interpreted_value="Nikon",
        source_engine="ExifTool",
    )
    r_et_dup_instance = MetadataRecord(
        record_id="exiftool:IFD0:Make:1",
        source="ExifTool",
        category="EXIF Metadata",
        tag_name="Make",
        namespace="IFD0",
        raw_value="Canon Inc.",
        interpreted_value="Canon Inc.",
        source_engine="ExifTool",
        instance_index=1,
    )

    merged = merge_metadata_records([r_int], [r_et_match, r_et_dup_instance])
    assert len(merged) == 2
    assert merged[0].discovered_by == ("exifread", "ExifTool")
    assert merged[0].tag_id == "0x010F"
    assert merged[0].engine_disagreement is None

    conflicted = merge_metadata_records([r_int], [r_et_conflict])
    assert len(conflicted) == 1
    assert conflicted[0].engine_disagreement is not None
    assert "Canon" in conflicted[0].engine_disagreement and "Nikon" in conflicted[0].engine_disagreement


@pytest.mark.parametrize("fmt,ext", [("GIF", "gif"), ("BMP", "bmp"), ("TIFF", "tiff"), ("WEBP", "webp"), ("PNG", "png"), ("JPEG", "jpg")])
def test_e2e_inspection_populates_diagnostics_and_capabilities(fmt: str, ext: str):
    raw = _encode(fmt, progressive=(fmt == "JPEG"))
    inspection = inspect_image(raw, f"sample.{ext}")
    inv = inspection.inventory
    assert inv is not None
    assert inv.coverage.format_capability is not None
    assert inv.coverage.file_signature is not None
    assert inv.coverage.file_signature["detected_format"] == fmt
    stage_ids = {s.stage_id for s in inv.coverage.stages}
    assert "exiftool" in stage_ids
    assert "container" in stage_ids
