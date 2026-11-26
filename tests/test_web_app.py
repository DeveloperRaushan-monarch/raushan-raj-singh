"""Security, privacy, API, and session-isolation tests for server.py."""

from __future__ import annotations

from fractions import Fraction
import http.client
from io import BytesIO
import json
import time
from unittest.mock import patch
from urllib.parse import quote

import pytest
from PIL import Image

from core.malware_models import (
    DatabaseFreshnessStatus,
    MalwareDetection,
    MalwareScanOutcome,
    MalwareScanResult,
)
from server import PixeltruthHTTPServer, PixeltruthRequestHandler, SessionStore, _serialize_inspection
from utils.validators import MAX_UPLOAD_BYTES


def _make_jpeg(*, with_gps: bool = False, make: str = "Canon") -> bytes:
    exif = Image.Exif()
    exif[271] = make
    if with_gps:
        exif[34853] = {
            1: "N",
            2: (Fraction(37), Fraction(48), Fraction(30)),
            3: "W",
            4: (Fraction(122), Fraction(24), Fraction(15)),
        }
    buf = BytesIO()
    Image.new("RGB", (32, 24), color=(80, 110, 140)).save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def _make_png() -> bytes:
    buf = BytesIO()
    Image.new("RGB", (24, 16), color=(120, 140, 160)).save(buf, format="PNG")
    return buf.getvalue()


class _FakeSocket:
    def __init__(self, raw_request: bytes) -> None:
        self._rfile = BytesIO(raw_request)
        self._wfile = BytesIO()

    def makefile(self, mode: str, *args, **kwargs):
        return self._rfile if "r" in mode else self._wfile

    def sendall(self, data: bytes) -> None:
        self._wfile.write(data)

    def close(self) -> None:
        pass


class _DummyServer:
    def __init__(self, store: SessionStore) -> None:
        self.session_store = store


@pytest.fixture()
def live_server():
    store = SessionStore(max_sessions=4, ttl_seconds=60)
    return _DummyServer(store), 0


def _request(
    server_or_port,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    hdrs = dict(headers or {})
    hdrs.setdefault("Host", "127.0.0.1")
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    raw_req = f"{method} {path} HTTP/1.1\r\n{header_lines}\r\n".encode("latin-1") + body
    sock = _FakeSocket(raw_req)
    PixeltruthRequestHandler(sock, ("127.0.0.1", 0), server_or_port)  # type: ignore[arg-type]
    raw_resp = sock._wfile.getvalue()

    class _RespSock:
        def makefile(self, mode: str, *args, **kwargs):
            return BytesIO(raw_resp)

    resp = http.client.HTTPResponse(_RespSock())  # type: ignore[arg-type]
    resp.begin()
    data = resp.read()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, resp_headers, data


def test_server_rejects_non_localhost_binding():
    with pytest.raises(ValueError, match="127.0.0.1"):
        PixeltruthHTTPServer(("0.0.0.0", 0))


def test_security_methods_routes_and_upload_limits(live_server):
    server, _ = live_server

    status, _, _ = _request(server, "DELETE", "/api/inspect")
    assert status == 405

    status, _, _ = _request(server, "GET", "/nonexistent")
    assert status == 404

    status, _, _ = _request(server, "GET", "/server.py")
    assert status == 404

    status, _, _ = _request(
        server,
        "POST",
        "/api/inspect",
        body=b"",
        headers={"Content-Length": str(MAX_UPLOAD_BYTES + 1), "X-Filename": "big.jpg"},
    )
    assert status == 413


def test_inspect_never_exposes_gps_and_redacts_paths(live_server):
    server, _ = live_server
    jpeg = _make_jpeg(with_gps=True)
    status, _, body = _request(
        server,
        "POST",
        "/api/inspect",
        body=jpeg,
        headers={
            "Content-Length": str(len(jpeg)),
            "X-Filename": quote(r"C:\Users\alice\Secret\photo.jpg"),
        },
    )
    assert status == 200
    payload = json.loads(body)
    assert payload["properties"]["filename"] == "photo.jpg"
    assert "Secret" not in json.dumps(payload)
    assert "37.808" not in json.dumps(payload)
    assert payload["assessment"]["outcome"] == "LOW CONCERN"

    sid = payload["session_id"]

    # Explicit GPS reveal and clear
    status, _, gps_body = _request(
        server, "POST", "/api/gps/reveal", headers={"X-Pixeltruth-Session": sid}
    )
    assert status == 200
    gps_data = json.loads(gps_body)
    assert gps_data["status"] == "Present"
    assert gps_data["latitude"] == pytest.approx(37.808333, abs=1e-4)

    status, _, _ = _request(
        server, "POST", "/api/gps/clear", headers={"X-Pixeltruth-Session": sid}
    )
    assert status == 200


def test_report_generation_defaults_and_session_token_isolation(live_server):
    server, _ = live_server
    jpeg = _make_jpeg(with_gps=True)
    status, _, body = _request(
        server,
        "POST",
        "/api/inspect",
        body=jpeg,
        headers={"Content-Length": str(len(jpeg)), "X-Filename": "evidence.jpg"},
    )
    assert status == 200
    sid_a = json.loads(body)["session_id"]

    # Generate PDF with default options (GPS excluded by default)
    req_json = json.dumps({}).encode("utf-8")
    status, _, rpt_body = _request(
        server,
        "POST",
        "/api/report/generate",
        body=req_json,
        headers={
            "X-Pixeltruth-Session": sid_a,
            "Content-Type": "application/json",
            "Content-Length": str(len(req_json)),
        },
    )
    assert status == 200
    rpt = json.loads(rpt_body)
    assert rpt["gps_included"] is False
    assert rpt["paths_redacted"] is True
    token = rpt["download_token"]

    # Download succeeds for owning session
    status, headers, pdf_bytes = _request(
        server,
        "GET",
        f"/api/report/download?token={token}",
        headers={"X-Pixeltruth-Session": sid_a},
    )
    assert status == 200
    assert headers["content-type"] == "application/pdf"
    assert pdf_bytes.startswith(b"%PDF-")

    # Cross-session download with valid token from session A is rejected
    _, _, s_body = _request(server, "POST", "/api/session")
    sid_b = json.loads(s_body)["session_id"]
    status, _, _ = _request(
        server,
        "GET",
        f"/api/report/download?token={token}",
        headers={"X-Pixeltruth-Session": sid_b},
    )
    assert status == 403


def test_ela_histogram_and_comparison_endpoints(live_server):
    server, _ = live_server
    jpeg = _make_jpeg()
    png = _make_png()

    status, _, body = _request(
        server,
        "POST",
        "/api/inspect",
        body=jpeg,
        headers={"Content-Length": str(len(jpeg)), "X-Filename": "sample.jpg"},
    )
    assert status == 200
    sid = json.loads(body)["session_id"]

    ela_req = json.dumps({"quality": 90, "error_scale": 10}).encode("utf-8")
    status, _, ela_body = _request(
        server,
        "POST",
        "/api/ela",
        body=ela_req,
        headers={
            "X-Pixeltruth-Session": sid,
            "Content-Type": "application/json",
            "Content-Length": str(len(ela_req)),
        },
    )
    assert status == 200
    assert "residual_png_base64" in json.loads(ela_body)

    status, _, hist_body = _request(
        server, "POST", "/api/histogram", headers={"X-Pixeltruth-Session": sid}
    )
    assert status == 200
    assert len(json.loads(hist_body)["combined"]) == 256

    # Comparison slots & swap
    status, _, _ = _request(
        server,
        "POST",
        "/api/compare/slot?slot=a",
        body=jpeg,
        headers={
            "X-Pixeltruth-Session": sid,
            "Content-Length": str(len(jpeg)),
            "X-Filename": "a.jpg",
        },
    )
    assert status == 200
    status, _, _ = _request(
        server,
        "POST",
        "/api/compare/slot?slot=b",
        body=png,
        headers={
            "X-Pixeltruth-Session": sid,
            "Content-Length": str(len(png)),
            "X-Filename": "b.png",
        },
    )
    assert status == 200
    status, _, _ = _request(
        server, "POST", "/api/compare/swap", headers={"X-Pixeltruth-Session": sid}
    )
    assert status == 200
    status, _, cmp_body = _request(
        server, "POST", "/api/compare", headers={"X-Pixeltruth-Session": sid}
    )
    assert status == 200
    assert len(json.loads(cmp_body)["metrics"]) >= 1


def test_session_store_expiry_and_bounded_eviction():
    store = SessionStore(max_sessions=2, ttl_seconds=0.05)
    s1 = store.create_session()
    s2 = store.create_session()
    assert store.count() == 2
    s3 = store.create_session()
    assert store.count() == 2
    assert store.get_session(s1.session_id) is None
    assert store.get_session(s3.session_id) is not None

    time.sleep(0.08)
    assert store.count() == 0
    assert store.get_session(s2.session_id) is None


def test_static_frontend_serves_all_8_stitch_screens_and_is_fully_offline(live_server):
    from pathlib import Path

    server, _ = live_server
    for route, expected_ctype in [
        ("/", "text/html"),
        ("/styles.css", "text/css"),
        ("/app.js", "application/javascript"),
    ]:
        status, headers, body = _request(server, "GET", route)
        assert status == 200
        assert expected_ctype in headers["content-type"]
        assert headers["cache-control"] == "no-store"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert body

    frontend_dir = Path(__file__).resolve().parents[1] / "frontend"
    html_text = (frontend_dir / "index.html").read_text(encoding="utf-8")
    css_text = (frontend_dir / "styles.css").read_text(encoding="utf-8")
    js_text = (frontend_dir / "app.js").read_text(encoding="utf-8")

    # Zero external runtime CDNs, fonts, or placeholder images
    for asset_text in (html_text, css_text, js_text):
        assert "cdn.tailwindcss.com" not in asset_text
        assert "fonts.googleapis.com" not in asset_text
        assert "lh3.googleusercontent.com" not in asset_text
        assert "https://" not in asset_text
        assert "http://" not in asset_text

    # All 8 Stitch screens and GPS link present
    for screen in (
        'data-screen="dashboard"',
        'data-screen="image-analysis"',
        'data-screen="metadata-explorer"',
        'data-screen="image-comparison"',
        'data-screen="error-level-analysis"',
        'data-screen="rgb-histogram"',
        'data-screen="forensic-reports"',
        'data-screen="about-project"',
    ):
        assert screen in html_text

    for nav in (
        'data-nav="dashboard"',
        'data-nav="image-analysis"',
        'data-nav="metadata-explorer"',
        'data-nav="gps-information"',
        'data-nav="image-comparison"',
        'data-nav="error-level-analysis"',
        'data-nav="rgb-histogram"',
        'data-nav="forensic-reports"',
        'data-nav="about-project"',
    ):
        assert nav in html_text

    # Dynamic Metadata Explorer controls present without unsafe raw metadata innerHTML
    for ctrl_id in (
        'id="meta-image-summary-card"',
        'id="meta-image-summary-grid"',
        'id="meta-coverage-card"',
        'id="meta-search"',
        'id="meta-filter-source"',
        'id="meta-filter-category"',
        'id="meta-filter-type"',
        'id="meta-filter-status"',
        'id="collapse-all-btn"',
        'id="copy-all-meta-btn"',
        'id="export-json-btn"',
        'id="export-csv-btn"',
        'id="meta-export-status"',
        'id="malware-scan-card"',
        'id="rpt-inc-malware"',
    ):
        assert ctrl_id in html_text


def test_api_inspect_serializes_inventory_stages_and_excludes_gps(live_server):
    from PIL import ImageCms
    from PIL.TiffImagePlugin import IFDRational

    server, _ = live_server
    exif = Image.Exif()
    exif[271] = "Canon"
    exif[0x9999] = "UnknownTagVal"
    exif_ifd = exif.get_ifd(0x8769)
    exif_ifd[33434] = IFDRational(1, 125)
    exif_ifd[0x927C] = b"RAW_MAKERNOTE_" + (b"\x01" * 80)
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
    }
    icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    buf = BytesIO()
    Image.new("RGB", (32, 24), color=(90, 120, 150)).save(
        buf, format="JPEG", exif=exif, icc_profile=icc
    )
    raw = buf.getvalue()

    status, _, body = _request(
        server,
        "POST",
        "/api/inspect",
        body=raw,
        headers={"Content-Length": str(len(raw)), "X-Filename": "rich.jpg"},
    )
    assert status == 200
    payload = json.loads(body)

    # Backward-compatible legacy fields preserved
    assert payload["assessment"]["outcome"] == "LOW CONCERN"
    assert isinstance(payload["metadata"], list)

    # Comprehensive inventory serialized with GPS excluded
    inv = payload["inventory"]
    assert inv["gps_present_indicator"] is True
    assert "37.808" not in json.dumps(inv)
    assert "Unknown / Unclassified Metadata" in inv["coverage"]["categories_found"]
    assert "ICC Colour Profile" in inv["coverage"]["categories_found"]
    assert any(r["tag_id"] == "0x9999" and r["is_unknown"] is True for r in inv["records"])
    assert any(s["stage_id"] == "makernotes" and s["completion_state"] == "PARTIAL" for s in inv["coverage"]["stages"])


def test_api_inspect_unsupported_and_partial_stages(live_server):
    server, _ = live_server
    bmp_buf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(bmp_buf, format="BMP")
    bmp = bmp_buf.getvalue()

    status, _, body = _request(
        server,
        "POST",
        "/api/inspect",
        body=bmp,
        headers={"Content-Length": str(len(bmp)), "X-Filename": "sample.bmp"},
    )
    assert status == 200
    inv = json.loads(body)["inventory"]
    assert "EXIF" in inv["coverage"]["unsupported_sources"]
    assert inv["coverage"]["total_records"] > 0


# ---------------------------------------------------------------------------
# Phase C — Malware Scan Backend Integration Tests
# ---------------------------------------------------------------------------


def _mock_scan_result(
    *,
    sha256: str = "a" * 64,
    status: MalwareScanOutcome = MalwareScanOutcome.NO_KNOWN_THREAT,
    detections: tuple[MalwareDetection, ...] = (),
    freshness: DatabaseFreshnessStatus = DatabaseFreshnessStatus.CURRENT,
    errors: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
    reason_code: str | None = "CLEAN",
) -> MalwareScanResult:
    return MalwareScanResult(
        file_hash_sha256=sha256,
        scanner_name="ClamAV",
        scanner_version="1.5.5",
        signature_database_version="28194",
        signature_database_timestamp="Wed Nov 25 11:56:59 2026",
        database_freshness=freshness,
        scan_started_at="2026-11-26T00:00:00+00:00",
        scan_completed_at="2026-11-26T00:00:01+00:00",
        scan_duration=0.05,
        scan_status=status,
        detection_count=len(detections),
        detections=detections,
        warnings=warnings,
        errors=errors,
        limitations=("ClamAV detects known signatures only.",),
        reason_code=reason_code,
    )


def test_api_inspect_clean_scan_and_session_storage(live_server):
    server, _ = live_server
    raw = _make_jpeg(with_gps=True)
    mocked = _mock_scan_result()

    with patch("server.scan_image_bytes", return_value=mocked) as mock_scan:
        status, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "/local/secret/photo.jpg"},
        )

    assert status == 200
    payload = json.loads(body)
    ms = payload["malware_scan"]
    assert ms["scan_status"] == "NO_KNOWN_THREAT"
    assert ms["outcome_label"] == "NO KNOWN THREATS DETECTED"
    assert ms["detection_count"] == 0
    assert ms["detections"] == []
    # Validated object and SHA-256 passed directly, no raw path leaked
    assert mock_scan.call_args.kwargs["validated_image"] is not None
    assert len(mock_scan.call_args.kwargs["file_hash_sha256"]) == 64
    assert "/local/secret" not in json.dumps(ms)
    # GPS excluded from malware_scan response
    assert "37.808" not in json.dumps(ms)
    # Stored in session state
    session = server.session_store.get_session(payload["session_id"])
    assert session is not None
    assert session.malware_scan == mocked


def test_api_inspect_single_and_multiple_malware_detections_preserve_names(live_server):
    server, _ = live_server
    raw = _make_jpeg()

    single = _mock_scan_result(
        status=MalwareScanOutcome.MALWARE_DETECTED,
        detections=(
            MalwareDetection(
                detection_name="Eicar-Signature",
                threat_category="Test Signature",
                affected_file_identifier="sample.jpg",
                scanner_verdict="FOUND",
            ),
        ),
        reason_code="THREAT_DETECTED",
    )
    with patch("server.scan_image_bytes", return_value=single):
        status, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "sample.jpg"},
        )
    assert status == 200
    p1 = json.loads(body)
    assert p1["malware_scan"]["scan_status"] == "MALWARE_DETECTED"
    assert p1["malware_scan"]["detection_count"] == 1
    assert p1["malware_scan"]["detections"][0]["detection_name"] == "Eicar-Signature"
    # PT-EA/1.0.0 assessment must remain independent of malware detection
    assert p1["assessment"]["outcome"] == "LOW CONCERN"

    multi = _mock_scan_result(
        status=MalwareScanOutcome.MALWARE_DETECTED,
        detections=(
            MalwareDetection(detection_name="Win.Trojan.Alpha-1", threat_category="Trojan"),
            MalwareDetection(detection_name="Html.Phishing.Beta-2", threat_category="Phishing"),
        ),
        reason_code="THREAT_DETECTED",
    )
    with patch("server.scan_image_bytes", return_value=multi):
        status, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "sample.jpg"},
        )
    assert status == 200
    p2 = json.loads(body)
    assert p2["malware_scan"]["detection_count"] == 2
    assert [d["detection_name"] for d in p2["malware_scan"]["detections"]] == [
        "Win.Trojan.Alpha-1",
        "Html.Phishing.Beta-2",
    ]
    assert p2["assessment"]["outcome"] == p1["assessment"]["outcome"]


@pytest.mark.parametrize(
    "reason_code,freshness,error_msg",
    [
        ("CLAMAV_NOT_INSTALLED", DatabaseFreshnessStatus.MISSING, "ClamAV is not installed or could not be located."),
        ("DATABASE_MISSING", DatabaseFreshnessStatus.MISSING, "ClamAV signature database is missing."),
        ("DATABASE_OUTDATED", DatabaseFreshnessStatus.OUTDATED, "ClamAV signature database is outdated."),
        ("SCAN_TIMEOUT", DatabaseFreshnessStatus.CURRENT, "ClamAV scan exceeded the 30s timeout."),
        ("MALFORMED_OUTPUT", DatabaseFreshnessStatus.CURRENT, "ClamAV returned malformed output."),
    ],
)
def test_api_inspect_incomplete_states_never_report_clean(
    live_server, reason_code: str, freshness: DatabaseFreshnessStatus, error_msg: str
):
    server, _ = live_server
    raw = _make_png()
    incomplete = _mock_scan_result(
        status=MalwareScanOutcome.SCAN_INCOMPLETE,
        freshness=freshness,
        errors=(error_msg,),
        reason_code=reason_code,
    )
    with patch("server.scan_image_bytes", return_value=incomplete):
        status, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "sample.png"},
        )

    assert status == 200
    payload = json.loads(body)
    assert payload["malware_scan"]["scan_status"] == "SCAN_INCOMPLETE"
    assert payload["malware_scan"]["reason_code"] == reason_code
    assert payload["malware_scan"]["outcome_label"] == "MALWARE SCAN INCOMPLETE"
    # Existing image inspection & assessment still succeed when scanner is unavailable
    assert payload["properties"]["image_format"] == "PNG"
    assert payload["assessment"]["outcome"] == "INSUFFICIENT EVIDENCE"


def test_api_inspect_unexpected_scanner_exception_handled_safely(live_server):
    server, _ = live_server
    raw = _make_png()

    with patch("server.scan_image_bytes", side_effect=RuntimeError("/private/var/folders/secret_tmp_path")):
        status, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "sample.png"},
        )

    assert status == 200
    payload = json.loads(body)
    ms = payload["malware_scan"]
    assert ms["scan_status"] == "SCAN_INCOMPLETE"
    assert ms["reason_code"] == "UNEXPECTED_ERROR"
    assert "/private/var/folders" not in json.dumps(ms)
    assert "secret_tmp_path" not in json.dumps(ms)


def test_serialize_inspection_missing_malware_scan_defaults_to_incomplete():
    from core.analysis import inspect_image
    from core.assessment_engine import assess_inspection

    raw = _make_png()
    insp = inspect_image(raw, "sample.png")
    assess = assess_inspection(insp)
    serialized = _serialize_inspection(insp, assess, malware_scan=None)
    assert serialized["malware_scan"]["scan_status"] == "SCAN_INCOMPLETE"
    assert serialized["malware_scan"]["reason_code"] == "SCAN_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Phase E — Metadata Exports (JSON/CSV) & Optional PDF Malware Section Tests
# ---------------------------------------------------------------------------


def test_metadata_export_json_and_csv_excludes_gps_and_sanitizes_formulas(live_server):
    import csv
    from io import StringIO

    server, _ = live_server
    exif = Image.Exif()
    exif[271] = "=CMD|' /C calc'!A0"
    exif[272] = 'Cam "Pro", Zürich\nLine2'
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
    }
    buf = BytesIO()
    Image.new("RGB", (24, 24), color=(100, 120, 140)).save(buf, format="JPEG", exif=exif)
    raw = buf.getvalue()

    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "formula.jpg"},
        )
    assert st == 200
    sid = json.loads(body)["session_id"]

    # JSON export
    st_j, hdr_j, body_j = _request(
        server,
        "GET",
        "/api/metadata/export?format=json",
        headers={"X-Pixeltruth-Session": sid},
    )
    assert st_j == 200
    assert "application/json" in hdr_j["content-type"]
    assert "pixeltruth_metadata_" in hdr_j["content-disposition"]
    assert body_j.decode("utf-8")
    assert "37.808" not in body_j.decode("utf-8")
    exported_json = json.loads(body_j)
    assert len(exported_json["records"]) > 0

    # CSV export
    st_c, hdr_c, body_c = _request(
        server,
        "GET",
        "/api/metadata/export?format=csv",
        headers={"X-Pixeltruth-Session": sid},
    )
    assert st_c == 200
    assert "text/csv" in hdr_c["content-type"]
    assert ".csv" in hdr_c["content-disposition"]
    csv_text = body_c.decode("utf-8")
    assert "37.808" not in csv_text
    rows = list(csv.reader(StringIO(csv_text)))
    assert rows[0][0] == "record_id"
    # Formula injection neutralized with leading apostrophe
    make_rows = [r for r in rows[1:] if r[3] == "Make"]
    assert make_rows and make_rows[0][9].startswith("'=CMD")
    # Quotes, commas, newlines preserved safely in CSV
    model_rows = [r for r in rows[1:] if r[3] == "Model"]
    assert model_rows and 'Cam "Pro"' in model_rows[0][9] and "\nLine2" in model_rows[0][9]

    # UTF-8 Unicode preserved via PNG XMP chunk
    from PIL import PngImagePlugin
    png_info = PngImagePlugin.PngInfo()
    png_info.add_text(
        "XML:com.adobe.xmp",
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Zürich Studio</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>',
    )
    pbuf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(pbuf, format="PNG", pnginfo=png_info)
    praw = pbuf.getvalue()
    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st_u, _, body_u = _request(
            server,
            "POST",
            "/api/inspect",
            body=praw,
            headers={"Content-Length": str(len(praw)), "X-Filename": "unicode.png"},
        )
    assert st_u == 200
    sid_u = json.loads(body_u)["session_id"]
    st_cu, _, body_cu = _request(
        server,
        "GET",
        "/api/metadata/export?format=csv",
        headers={"X-Pixeltruth-Session": sid_u},
    )
    assert st_cu == 200
    assert "Zürich Studio" in body_cu.decode("utf-8")


def test_metadata_export_session_isolation_and_error_cases(live_server):
    server, _ = live_server
    # Missing/invalid session -> 401
    st1, _, _ = _request(server, "GET", "/api/metadata/export?format=json")
    assert st1 == 401

    # Valid empty session without inspection -> 400
    st_s, _, body_s = _request(server, "POST", "/api/session")
    assert st_s == 200
    sid_empty = json.loads(body_s)["session_id"]
    st2, _, _ = _request(
        server,
        "GET",
        "/api/metadata/export?format=json",
        headers={"X-Pixeltruth-Session": sid_empty},
    )
    assert st2 == 400

    # Upload in session A; session B still cannot export session A's metadata
    raw = _make_png()
    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st_a, _, body_a = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "a.png"},
        )
    assert st_a == 200
    sid_a = json.loads(body_a)["session_id"]

    st_b, _, _ = _request(
        server,
        "GET",
        "/api/metadata/export?format=json",
        headers={"X-Pixeltruth-Session": sid_empty},
    )
    assert st_b == 400

    # Unsupported format -> 400
    st_bad, _, _ = _request(
        server,
        "GET",
        "/api/metadata/export?format=xml",
        headers={"X-Pixeltruth-Session": sid_a},
    )
    assert st_bad == 400


def test_report_generate_malware_opt_in_and_default_exclusion(live_server):
    server, _ = live_server
    raw = _make_jpeg(with_gps=True)
    infected = _mock_scan_result(
        status=MalwareScanOutcome.MALWARE_DETECTED,
        detections=(MalwareDetection(detection_name="Eicar-Signature", threat_category="Test Signature"),),
        reason_code="THREAT_DETECTED",
    )
    with patch("server.scan_image_bytes", return_value=infected):
        st, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "sample.jpg"},
        )
    assert st == 200
    sid = json.loads(body)["session_id"]

    # Default: malware section excluded
    req_default = json.dumps({"include_assessment": True}).encode("utf-8")
    st1, _, b1 = _request(
        server,
        "POST",
        "/api/report/generate",
        body=req_default,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(req_default)),
            "X-Pixeltruth-Session": sid,
        },
    )
    assert st1 == 200
    r1 = json.loads(b1)
    assert "Malware & Security Analysis" not in r1["included_sections"]
    assert r1["gps_included"] is False

    # Explicit opt-in: malware section included, GPS still excluded by default
    req_optin = json.dumps({"include_assessment": True, "include_malware_scan": True}).encode("utf-8")
    st2, _, b2 = _request(
        server,
        "POST",
        "/api/report/generate",
        body=req_optin,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(req_optin)),
            "X-Pixeltruth-Session": sid,
        },
    )
    assert st2 == 200
    r2 = json.loads(b2)
    assert "Malware & Security Analysis" in r2["included_sections"]
    assert r2["gps_included"] is False


def test_metadata_export_csv_empty_inventory(live_server):
    import csv
    from io import StringIO
    from core.metadata_models import MetadataExtractionCoverage, MetadataInventory

    server, _ = live_server
    raw = _make_png()
    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "empty.png"},
        )
    assert st == 200
    sid = json.loads(body)["session_id"]

    # Replace session inventory with a zero-record MetadataInventory
    session = server.session_store.get_session(sid)
    assert session is not None and session.active_inspection is not None
    empty_inv = MetadataInventory(
        records=(),
        coverage=MetadataExtractionCoverage(
            stages=(),
            total_records=0,
            categories_found=(),
            unsupported_sources=(),
            warnings=(),
            limitations=(),
        ),
        gps_present_indicator=False,
    )
    session.active_inspection = type(session.active_inspection)(
        properties=session.active_inspection.properties,
        metadata=session.active_inspection.metadata,
        sha256=session.active_inspection.sha256,
        warnings=session.active_inspection.warnings,
        findings=session.active_inspection.findings,
        inventory=empty_inv,
    )

    st_csv, hdr_csv, body_csv = _request(
        server,
        "GET",
        "/api/metadata/export?format=csv",
        headers={"X-Pixeltruth-Session": sid},
    )
    assert st_csv == 200
    assert "text/csv" in hdr_csv["content-type"]
    csv_text = body_csv.decode("utf-8")
    rows = list(csv.reader(StringIO(csv_text)))
    assert rows == [[
        "record_id",
        "source",
        "category",
        "tag_name",
        "tag_id",
        "namespace",
        "path",
        "data_type",
        "status",
        "interpreted_value",
        "raw_value",
        "is_unknown",
        "is_hierarchical",
        "limitations",
        "source_engine",
        "source_container",
        "group",
        "unit",
        "extraction_status",
        "discovered_by",
        "engine_disagreement",
    ]]


def test_gps_reveal_clear_reset_on_new_upload_and_session_isolation(live_server):
    server, _ = live_server
    gps_jpg = _make_jpeg(with_gps=True)
    plain_png = _make_png()

    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st1, _, b1 = _request(
            server,
            "POST",
            "/api/inspect",
            body=gps_jpg,
            headers={"Content-Length": str(len(gps_jpg)), "X-Filename": "gps.jpg"},
        )
    assert st1 == 200
    sid1 = json.loads(b1)["session_id"]

    # Reveal GPS in session 1
    st_rev, _, b_rev = _request(
        server,
        "POST",
        "/api/gps/reveal",
        headers={"X-Pixeltruth-Session": sid1},
    )
    assert st_rev == 200
    rev = json.loads(b_rev)
    assert rev["status"] == "Present"
    assert rev["gps_state"] == "GPS_COORDINATES_AVAILABLE"
    assert "GPSLatitude" in rev["raw_tags"]

    # Second session cannot see session 1's GPS
    st_s2, _, b_s2 = _request(server, "POST", "/api/session")
    assert st_s2 == 200
    sid2 = json.loads(b_s2)["session_id"]
    st_s2_rev, _, _ = _request(
        server,
        "POST",
        "/api/gps/reveal",
        headers={"X-Pixeltruth-Session": sid2},
    )
    assert st_s2_rev == 400

    # Uploading a new image in session 1 resets GPS state
    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st2, _, _ = _request(
            server,
            "POST",
            "/api/inspect",
            body=plain_png,
            headers={"Content-Length": str(len(plain_png)), "X-Filename": "plain.png", "X-Pixeltruth-Session": sid1},
        )
    assert st2 == 200
    session1 = server.session_store.get_session(sid1)
    assert session1 is not None and session1.gps_result is None


def test_metadata_record_consistency_across_api_and_exports(live_server):
    import csv
    from io import StringIO

    server, _ = live_server
    raw = _make_jpeg(make="Canon")
    with patch("server.scan_image_bytes", return_value=_mock_scan_result()):
        st, _, body = _request(
            server,
            "POST",
            "/api/inspect",
            body=raw,
            headers={"Content-Length": str(len(raw)), "X-Filename": "consistency.jpg"},
        )
    assert st == 200
    payload = json.loads(body)
    sid = payload["session_id"]

    api_make = next(r for r in payload["inventory"]["records"] if r["tag_name"] == "Make")
    assert api_make["source"] == "EXIF"
    assert api_make["tag_id"] == "0x010F"
    assert api_make["path"] == ["EXIF", "Image", "Make"]
    assert api_make["raw_value"] == "Canon"

    st_j, _, bj = _request(server, "GET", "/api/metadata/export?format=json", headers={"X-Pixeltruth-Session": sid})
    assert st_j == 200
    exp_make = next(r for r in json.loads(bj)["records"] if r["tag_name"] == "Make")
    assert exp_make == api_make

    st_c, _, bc = _request(server, "GET", "/api/metadata/export?format=csv", headers={"X-Pixeltruth-Session": sid})
    assert st_c == 200
    csv_rows = list(csv.reader(StringIO(bc.decode("utf-8"))))
    csv_make = next(r for r in csv_rows[1:] if r[3] == "Make")
    assert csv_make[1] == "EXIF"
    assert csv_make[4] == "0x010F"
    assert csv_make[6] == "EXIF / Image / Make"
    assert csv_make[10] == "Canon"

