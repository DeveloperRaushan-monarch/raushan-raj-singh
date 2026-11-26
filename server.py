"""Local-only Python standard-library HTTP server for the PIXELTRUTH Stitch UI."""

from __future__ import annotations

import base64
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from core.analysis import inspect_image
from core.assessment_engine import assess_inspection
from core.assessment_models import AssessmentResult
from core.comparison import compare_images
from core.ela import ELAError, ELAResult, calculate_ela
from core.gps import GPSResult, extract_gps
from core.histogram import HistogramError, HistogramResult, calculate_rgb_histogram
from core.malware_models import MalwareScanOutcome, MalwareScanResult
from core.malware_scanner import scan_image_bytes
from core.metadata_models import sanitize_csv_cell
from core.models import ImageInspection, MetadataStatus
from core.report import ReportOptions, ReportResult, generate_pdf_report, sanitize_display_filename
from utils.validators import ImageValidationError, MAX_UPLOAD_BYTES, ValidatedImage


FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8501
MAX_SESSIONS = 16
SESSION_TTL_SECONDS = 1800
MAX_RECENT_RECORDS = 20

STATIC_ROUTES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


@dataclass
class SessionState:
    """In-memory, non-persistent state for a single local browser session."""

    session_id: str
    last_access: float
    active_bytes: bytes | None = None
    active_inspection: ImageInspection | None = None
    active_assessment: AssessmentResult | None = None
    malware_scan: MalwareScanResult | None = None
    gps_result: GPSResult | None = None
    ela_result: ELAResult | None = None
    histogram_result: HistogramResult | None = None
    report_result: ReportResult | None = None
    report_token: str | None = None
    compare_a: tuple[bytes, str] | None = None
    compare_b: tuple[bytes, str] | None = None
    recent_records: list[dict[str, str]] = field(default_factory=list)


class SessionStore:
    """Thread-safe bounded in-memory session store with TTL expiry."""

    def __init__(
        self,
        *,
        max_sessions: int = MAX_SESSIONS,
        ttl_seconds: float = SESSION_TTL_SECONDS,
    ) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds

    def _prune_locked(self, now: float) -> None:
        expired = [
            sid
            for sid, state in self._sessions.items()
            if (now - state.last_access) > self._ttl_seconds
        ]
        for sid in expired:
            del self._sessions[sid]

        while len(self._sessions) >= self._max_sessions:
            oldest_sid = min(
                self._sessions, key=lambda sid: self._sessions[sid].last_access
            )
            del self._sessions[oldest_sid]

    def create_session(self) -> SessionState:
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            sid = secrets.token_urlsafe(32)
            state = SessionState(session_id=sid, last_access=now)
            self._sessions[sid] = state
            return state

    def get_session(self, session_id: str | None) -> SessionState | None:
        if not session_id:
            return None
        now = time.monotonic()
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None
            if (now - state.last_access) > self._ttl_seconds:
                del self._sessions[session_id]
                return None
            state.last_access = now
            return state

    def get_or_create(self, session_id: str | None) -> SessionState:
        existing = self.get_session(session_id)
        if existing is not None:
            return existing
        return self.create_session()

    def count(self) -> int:
        now = time.monotonic()
        with self._lock:
            expired = [
                sid
                for sid, state in self._sessions.items()
                if (now - state.last_access) > self._ttl_seconds
            ]
            for sid in expired:
                del self._sessions[sid]
            return len(self._sessions)


def _serialize_inspection(
    inspection: ImageInspection,
    assessment: AssessmentResult,
    malware_scan: MalwareScanResult | None = None,
) -> dict[str, Any]:
    props = inspection.properties
    effective_malware_scan = malware_scan or MalwareScanResult(
        file_hash_sha256=inspection.sha256,
        scan_status=MalwareScanOutcome.SCAN_INCOMPLETE,
        errors=("Malware scan result is unavailable.",),
        reason_code="SCAN_UNAVAILABLE",
    )
    orientation_field = next(
        (f for f in inspection.metadata if f.key == "orientation"), None
    )
    orientation_display = (
        orientation_field.value
        if orientation_field and orientation_field.status is MetadataStatus.PRESENT and orientation_field.value
        else "Not available"
    )
    return {
        "properties": {
            "filename": sanitize_display_filename(props.filename, redact_paths=True),
            "file_size_bytes": props.file_size_bytes,
            "image_format": props.image_format,
            "mime_type": props.mime_type,
            "width": props.width,
            "height": props.height,
            "aspect_ratio": props.aspect_ratio,
            "megapixels": props.megapixels,
            "color_mode": props.color_mode,
            "bit_depth_per_channel": props.bit_depth_per_channel,
            "frame_count": props.frame_count,
            "has_transparency": props.has_transparency,
            "extension_mismatch": props.extension_mismatch,
            "orientation": orientation_display,
        },
        "sha256": inspection.sha256,
        "warnings": list(inspection.warnings),
        "metadata": [
            {
                "key": f.key,
                "label": f.label,
                "value": f.value if f.value is not None else "Not available",
                "status": f.status.value,
                "source": f.source or "EXIF",
                "note": f.note or "",
            }
            for f in inspection.metadata
        ],
        "legacy_findings": [
            {
                "finding_id": f.finding_id,
                "category": f.category,
                "title": f.title,
                "relevance": f.relevance,
                "observed_evidence": f.observed_evidence,
                "explanation": f.explanation,
                "possible_interpretations": f.possible_interpretations,
                "confidence_limitations": f.confidence_limitations,
                "recommended_next_check": f.recommended_next_check,
            }
            for f in inspection.findings
        ],
        "assessment": assessment.to_dict(),
        "inventory": (
            inspection.inventory.to_dict()
            if inspection.inventory is not None
            else None
        ),
        "malware_scan": effective_malware_scan.to_dict(),
    }


class PixeltruthHTTPServer(ThreadingHTTPServer):
    """Localhost-bound HTTP server carrying an isolated in-memory SessionStore."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        session_store: SessionStore | None = None,
    ) -> None:
        if server_address[0] != BIND_HOST:
            raise ValueError(f"PIXELTRUTH server must bind exclusively to {BIND_HOST}.")
        self.session_store = session_store or SessionStore()
        super().__init__(server_address, PixeltruthRequestHandler)


class PixeltruthRequestHandler(BaseHTTPRequestHandler):
    """Strict request handler for static Stitch assets and local forensic APIs."""

    server: PixeltruthHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        # Never log filenames, metadata, paths, or user bytes.
        return

    def _send_common_headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._send_common_headers(status, "application/json; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_body(self, *, max_bytes: int) -> bytes | None:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._send_error_json(HTTPStatus.LENGTH_REQUIRED, "Content-Length header is required.")
            return None
        try:
            length = int(raw_len)
        except ValueError:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid Content-Length header.")
            return None
        if length < 0:
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Invalid Content-Length header.")
            return None
        if length > max_bytes:
            self._send_error_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Upload exceeds maximum allowed size ({max_bytes // (1024 * 1024)} MB).",
            )
            return None
        return self.rfile.read(length)

    def _read_json_body(self) -> dict[str, Any] | None:
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send_error_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Expected application/json.")
            return None
        raw = self._read_body(max_bytes=65536)
        if raw is None:
            return None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "Malformed JSON payload.")
            return None
        if not isinstance(parsed, dict):
            self._send_error_json(HTTPStatus.BAD_REQUEST, "JSON payload must be an object.")
            return None
        return parsed

    def _session_id_header(self) -> str | None:
        return self.headers.get("X-Pixeltruth-Session")

    def _require_session(self) -> SessionState | None:
        state = self.server.session_store.get_session(self._session_id_header())
        if state is None:
            self._send_error_json(HTTPStatus.UNAUTHORIZED, "Valid local session is required.")
            return None
        return state

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        if route in STATIC_ROUTES:
            filename, content_type = STATIC_ROUTES[route]
            target = (FRONTEND_DIR / filename).resolve()
            if not target.is_file() or target.parent != FRONTEND_DIR.resolve():
                self._send_error_json(HTTPStatus.NOT_FOUND, "Frontend asset not found.")
                return
            data = target.read_bytes()
            self._send_common_headers(HTTPStatus.OK, content_type, len(data))
            self.end_headers()
            self.wfile.write(data)
            return

        if route == "/api/session/recent":
            state = self._require_session()
            if state is None:
                return
            self._send_json(
                HTTPStatus.OK,
                {"session_id": state.session_id, "recent_records": state.recent_records},
            )
            return

        if route == "/api/metadata/export":
            state = self._require_session()
            if state is None:
                return
            if state.active_inspection is None or state.active_inspection.inventory is None:
                self._send_error_json(
                    HTTPStatus.BAD_REQUEST,
                    "No metadata inventory is active in this session.",
                )
                return
            qs = parse_qs(parsed.query)
            fmt = ((qs.get("format") or ["json"])[0] or "json").strip().lower()
            if fmt not in {"json", "csv"}:
                self._send_error_json(
                    HTTPStatus.BAD_REQUEST,
                    "Unsupported export format. Expected 'json' or 'csv'.",
                )
                return

            inv_dict = state.active_inspection.inventory.to_dict()
            digest_prefix = state.active_inspection.sha256[:12]

            if fmt == "json":
                payload = json.dumps(inv_dict, indent=2, ensure_ascii=False).encode("utf-8")
                self._send_common_headers(HTTPStatus.OK, "application/json; charset=utf-8", len(payload))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="pixeltruth_metadata_{digest_prefix}.json"',
                )
                self.end_headers()
                self.wfile.write(payload)
                return

            csv_buf = StringIO()
            writer = csv.writer(csv_buf)
            writer.writerow(
                [
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
                ]
            )
            for rec in inv_dict.get("records", []):
                raw_val = rec.get("raw_value")
                if isinstance(raw_val, (dict, list)):
                    raw_cell: Any = json.dumps(raw_val, ensure_ascii=False)
                else:
                    raw_cell = raw_val
                path_val = " / ".join(rec.get("path") or [])
                writer.writerow(
                    [
                        sanitize_csv_cell(rec.get("record_id")),
                        sanitize_csv_cell(rec.get("source")),
                        sanitize_csv_cell(rec.get("category")),
                        sanitize_csv_cell(rec.get("tag_name")),
                        sanitize_csv_cell(rec.get("tag_id")),
                        sanitize_csv_cell(rec.get("namespace")),
                        sanitize_csv_cell(path_val),
                        sanitize_csv_cell(rec.get("data_type")),
                        sanitize_csv_cell(rec.get("status")),
                        sanitize_csv_cell(rec.get("interpreted_value")),
                        sanitize_csv_cell(raw_cell),
                        sanitize_csv_cell(rec.get("is_unknown")),
                        sanitize_csv_cell(rec.get("is_hierarchical")),
                        sanitize_csv_cell(rec.get("limitations")),
                    ]
                )
            csv_bytes = csv_buf.getvalue().encode("utf-8")
            self._send_common_headers(HTTPStatus.OK, "text/csv; charset=utf-8", len(csv_bytes))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="pixeltruth_metadata_{digest_prefix}.csv"',
            )
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        if route == "/api/report/download":
            qs = parse_qs(parsed.query)
            token = (qs.get("token") or [None])[0]
            sid = self._session_id_header() or (qs.get("session") or [None])[0]
            state = self.server.session_store.get_session(sid)
            if (
                state is None
                or not token
                or state.report_result is None
                or state.report_token is None
                or not secrets.compare_digest(token, state.report_token)
            ):
                self._send_error_json(HTTPStatus.FORBIDDEN, "Invalid or expired report download token.")
                return
            pdf = state.report_result.pdf_bytes
            digest_prefix = (
                state.active_inspection.sha256[:12]
                if state.active_inspection is not None
                else "report"
            )
            self._send_common_headers(HTTPStatus.OK, "application/pdf", len(pdf))
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="pixeltruth_report_{digest_prefix}.pdf"',
            )
            self.end_headers()
            self.wfile.write(pdf)
            return

        if route.startswith("/api/"):
            self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed for this route.")
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        if route == "/api/session":
            state = self.server.session_store.create_session()
            self._send_json(
                HTTPStatus.OK,
                {"session_id": state.session_id, "recent_records": state.recent_records},
            )
            return

        if route == "/api/inspect":
            raw = self._read_body(max_bytes=MAX_UPLOAD_BYTES)
            if raw is None:
                return
            raw_name = unquote(self.headers.get("X-Filename") or "upload.bin")
            try:
                inspection = inspect_image(raw, raw_name)
            except ImageValidationError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return

            assessment = assess_inspection(inspection)
            safe_name = sanitize_display_filename(inspection.properties.filename, redact_paths=True)
            props = inspection.properties
            validated = ValidatedImage(
                image_format=props.image_format,
                width=props.width,
                height=props.height,
                frame_dimensions=((props.width, props.height),),
                color_mode=props.color_mode,
                frame_count=props.frame_count,
                has_transparency=props.has_transparency,
                bit_depth_per_channel=props.bit_depth_per_channel,
                extension_mismatch=props.extension_mismatch,
            )
            try:
                malware_scan = scan_image_bytes(
                    raw,
                    safe_name,
                    validated_image=validated,
                    file_hash_sha256=inspection.sha256,
                )
            except Exception:
                malware_scan = MalwareScanResult(
                    file_hash_sha256=inspection.sha256,
                    scan_status=MalwareScanOutcome.SCAN_INCOMPLETE,
                    errors=("Malware scan failed due to an unexpected internal scanner error.",),
                    reason_code="UNEXPECTED_ERROR",
                )

            state = self.server.session_store.get_or_create(self._session_id_header())
            state.active_bytes = raw
            state.active_inspection = inspection
            state.active_assessment = assessment
            state.malware_scan = malware_scan
            state.gps_result = None
            state.ela_result = None
            state.histogram_result = None
            state.report_result = None
            state.report_token = None

            state.recent_records.insert(
                0,
                {
                    "filename": safe_name,
                    "format": inspection.properties.image_format,
                    "dimensions": f"{inspection.properties.width} × {inspection.properties.height}",
                    "sha256_prefix": inspection.sha256[:16] + "...",
                    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "outcome": assessment.outcome.value,
                },
            )
            state.recent_records = state.recent_records[:MAX_RECENT_RECORDS]

            payload = _serialize_inspection(inspection, assessment, malware_scan=malware_scan)
            payload["session_id"] = state.session_id
            payload["recent_records"] = state.recent_records
            self._send_json(HTTPStatus.OK, payload)
            return

        if route == "/api/gps/reveal":
            state = self._require_session()
            if state is None:
                return
            if state.active_bytes is None or state.active_inspection is None:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "No validated image is active in this session.")
                return
            gps = extract_gps(state.active_bytes, state.active_inspection.properties.image_format)
            state.gps_result = gps
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": gps.status.value,
                    "latitude": gps.latitude,
                    "longitude": gps.longitude,
                    "altitude_meters": gps.altitude_meters,
                    "timestamp_utc": gps.timestamp_utc,
                    "note": gps.note or "",
                },
            )
            return

        if route == "/api/gps/clear":
            state = self._require_session()
            if state is None:
                return
            state.gps_result = None
            state.report_result = None
            state.report_token = None
            self._send_json(HTTPStatus.OK, {"cleared": True})
            return

        if route == "/api/ela":
            state = self._require_session()
            if state is None:
                return
            if state.active_bytes is None or state.active_inspection is None:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "No validated image is active in this session.")
                return
            body = self._read_json_body()
            if body is None:
                return
            try:
                quality = int(body.get("quality", 90))
                error_scale = int(body.get("error_scale", 10))
                ela = calculate_ela(state.active_bytes, quality=quality, error_scale=error_scale)
            except (TypeError, ValueError, ELAError, ImageValidationError) as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            state.ela_result = ela
            state.report_result = None
            state.report_token = None
            self._send_json(
                HTTPStatus.OK,
                {
                    "width": ela.width,
                    "height": ela.height,
                    "quality": ela.quality,
                    "error_scale": ela.error_scale,
                    "mean_absolute_difference": ela.mean_absolute_difference,
                    "maximum_channel_difference": ela.maximum_channel_difference,
                    "changed_pixel_percent": ela.changed_pixel_percent,
                    "residual_png_base64": base64.b64encode(ela.residual_png).decode("ascii"),
                    "method": ela.method,
                    "limitations": ela.limitations,
                },
            )
            return

        if route == "/api/histogram":
            state = self._require_session()
            if state is None:
                return
            if state.active_bytes is None or state.active_inspection is None:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "No validated image is active in this session.")
                return
            try:
                hist = calculate_rgb_histogram(
                    state.active_bytes,
                    sanitize_display_filename(state.active_inspection.properties.filename),
                )
            except (HistogramError, ImageValidationError) as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            state.histogram_result = hist
            state.report_result = None
            state.report_token = None
            self._send_json(
                HTTPStatus.OK,
                {
                    "width": hist.width,
                    "height": hist.height,
                    "frame_count": hist.frame_count,
                    "pixel_count": hist.pixel_count,
                    "red": list(hist.red),
                    "green": list(hist.green),
                    "blue": list(hist.blue),
                    "combined": list(hist.combined),
                    "method": hist.method,
                    "limitations": hist.limitations,
                },
            )
            return

        if route == "/api/compare/slot":
            qs = parse_qs(parsed.query)
            slot = (qs.get("slot") or [None])[0]
            if slot not in {"a", "b"}:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Query parameter 'slot' must be 'a' or 'b'.")
                return
            raw = self._read_body(max_bytes=MAX_UPLOAD_BYTES)
            if raw is None:
                return
            raw_name = unquote(self.headers.get("X-Filename") or f"image_{slot}.bin")
            try:
                inspection = inspect_image(raw, raw_name)
            except ImageValidationError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            state = self.server.session_store.get_or_create(self._session_id_header())
            safe_name = sanitize_display_filename(inspection.properties.filename, redact_paths=True)
            if slot == "a":
                state.compare_a = (raw, safe_name)
            else:
                state.compare_b = (raw, safe_name)
            self._send_json(
                HTTPStatus.OK,
                {
                    "session_id": state.session_id,
                    "slot": slot,
                    "filename": safe_name,
                    "dimensions": f"{inspection.properties.width} × {inspection.properties.height} px",
                    "file_size_bytes": inspection.properties.file_size_bytes,
                    "sha256": inspection.sha256,
                },
            )
            return

        if route == "/api/compare/swap":
            state = self._require_session()
            if state is None:
                return
            state.compare_a, state.compare_b = state.compare_b, state.compare_a
            self._send_json(HTTPStatus.OK, {"swapped": True})
            return

        if route == "/api/compare":
            state = self._require_session()
            if state is None:
                return
            if state.compare_a is None or state.compare_b is None:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "Upload both Image A and Image B before comparing.")
                return
            try:
                result = compare_images(
                    state.compare_a[0], state.compare_a[1],
                    state.compare_b[0], state.compare_b[1],
                )
            except ImageValidationError as exc:
                self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "metrics": [
                        {
                            "label": m.label,
                            "reference_value": m.reference_value,
                            "suspect_value": m.suspect_value,
                            "matches": m.matches,
                        }
                        for m in result.metrics
                    ],
                    "metadata_differences": [
                        {
                            "label": d.label,
                            "reference_value": d.reference_value,
                            "suspect_value": d.suspect_value,
                        }
                        for d in result.metadata_differences
                    ],
                    "sampled_pixel_similarity": result.sampled_pixel_similarity,
                    "similarity_note": result.similarity_note,
                },
            )
            return

        if route == "/api/report/generate":
            state = self._require_session()
            if state is None:
                return
            if state.active_inspection is None or state.active_assessment is None:
                self._send_error_json(HTTPStatus.BAD_REQUEST, "No validated image is active in this session.")
                return
            body = self._read_json_body()
            if body is None:
                return
            include_gps = bool(body.get("include_gps", False))
            options = ReportOptions(
                include_properties=bool(body.get("include_properties", True)),
                include_metadata=bool(body.get("include_metadata", True)),
                include_assessment=bool(body.get("include_assessment", True)),
                include_ela=bool(body.get("include_ela", False)) and state.ela_result is not None,
                include_histogram=bool(body.get("include_histogram", False)) and state.histogram_result is not None,
                include_gps=include_gps and state.gps_result is not None,
                include_malware_scan=bool(body.get("include_malware_scan", False)),
                redact_local_paths=bool(body.get("redact_local_paths", True)),
            )
            report = generate_pdf_report(
                state.active_inspection,
                assessment=state.active_assessment,
                options=options,
                ela_result=state.ela_result if options.include_ela else None,
                histogram_result=state.histogram_result if options.include_histogram else None,
                gps_result=state.gps_result if options.include_gps else None,
                malware_scan=state.malware_scan if options.include_malware_scan else None,
            )
            token = secrets.token_urlsafe(24)
            state.report_result = report
            state.report_token = token
            self._send_json(
                HTTPStatus.OK,
                {
                    "report_id": report.report_id,
                    "generated_at_utc": report.generated_at_utc,
                    "included_sections": list(report.included_sections),
                    "gps_included": report.gps_included,
                    "paths_redacted": report.paths_redacted,
                    "display_filename": report.display_filename,
                    "rule_set_version": report.rule_set_version,
                    "download_token": token,
                },
            )
            return

        if route in STATIC_ROUTES:
            self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, "POST is not allowed for static assets.")
            return

        self._send_error_json(HTTPStatus.NOT_FOUND, "Route not found.")

    def _reject_method(self) -> None:
        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, "HTTP method not allowed.")

    do_PUT = _reject_method
    do_DELETE = _reject_method
    do_PATCH = _reject_method
    do_HEAD = _reject_method


def serve(port: int = DEFAULT_PORT) -> None:
    """Start the local-only PIXELTRUTH web server on 127.0.0.1."""
    server = PixeltruthHTTPServer((BIND_HOST, port))
    print(f"PIXELTRUTH running locally at http://{BIND_HOST}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
