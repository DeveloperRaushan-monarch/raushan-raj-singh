"""Monochrome A4 PDF forensic inspection report generator (Phase 4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
import posixpath
import uuid
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.assessment_engine import BOUNDARY_STATEMENT, assess_inspection
from core.assessment_models import AssessmentResult
from core.ela import ELAResult
from core.gps import GPSResult
from core.histogram import HistogramResult
from core.malware_models import MalwareScanOutcome, MalwareScanResult
from core.models import ImageInspection, MetadataStatus


_INK = colors.HexColor("#111111")
_MUTED = colors.HexColor("#555555")
_BORDER = colors.HexColor("#CCCCCC")
_SURFACE = colors.HexColor("#F5F5F5")
_HEADER_BG = colors.HexColor("#E8E8E8")


@dataclass(frozen=True)
class ReportOptions:
    """User-selected report sections and privacy defaults."""

    include_properties: bool = True
    include_metadata: bool = True
    include_assessment: bool = True
    include_ela: bool = False
    include_histogram: bool = False
    include_gps: bool = False
    include_malware_scan: bool = False
    redact_local_paths: bool = True


@dataclass(frozen=True)
class ReportResult:
    """Generated PDF report bytes and metadata reflecting selected options."""

    report_id: str
    generated_at_utc: str
    pdf_bytes: bytes
    included_sections: tuple[str, ...]
    gps_included: bool
    paths_redacted: bool
    rule_set_version: str
    display_filename: str


def sanitize_display_filename(filename: str, *, redact_paths: bool = True) -> str:
    """Return a display filename with macOS/POSIX and Windows paths stripped when enabled."""
    if not filename or not filename.strip():
        return "Unnamed image"
    if not redact_paths:
        return filename.strip()
    normalized = filename.strip().replace("\\", "/")
    base = posixpath.basename(normalized.rstrip("/"))
    return base or "Unnamed image"


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    safe_text = escape(str(text) if text is not None else "")
    return Paragraph(safe_text.replace("\n", "<br/>"), style)


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "PTTitle",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=_INK,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "PTSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=_MUTED,
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "PTH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=_INK,
            spaceBefore=10,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "PTBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12.5,
            textColor=_INK,
            spaceAfter=4,
        ),
        "muted": ParagraphStyle(
            "PTMuted",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=_MUTED,
            spaceAfter=4,
        ),
        "mono": ParagraphStyle(
            "PTMono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10.5,
            textColor=_INK,
            wordWrap="CJK",
        ),
        "cell": ParagraphStyle(
            "PTCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=_INK,
            wordWrap="CJK",
        ),
        "cell_bold": ParagraphStyle(
            "PTCellBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=_INK,
        ),
    }


def _styled_table(
    rows: list[list[Paragraph]],
    col_widths: list[float],
    *,
    repeat_rows: int = 1,
) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=repeat_rows)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
                ("TEXTCOLOR", (0, 0), (-1, -1), _INK),
                ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def generate_pdf_report(
    inspection: ImageInspection,
    *,
    assessment: AssessmentResult | None = None,
    options: ReportOptions | None = None,
    ela_result: ELAResult | None = None,
    histogram_result: HistogramResult | None = None,
    gps_result: GPSResult | None = None,
    malware_scan: MalwareScanResult | None = None,
    report_id: str | None = None,
    generated_at_utc: str | None = None,
) -> ReportResult:
    """Generate a monochrome A4 PDF report from existing inspection and assessment results."""
    opts = options or ReportOptions()
    resolved_assessment = assessment if assessment is not None else assess_inspection(inspection)
    resolved_id = report_id or f"PT-RPT-{inspection.sha256[:8].upper()}-{uuid.uuid4().hex[:6].upper()}"
    resolved_time = generated_at_utc or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    display_name = sanitize_display_filename(
        inspection.properties.filename,
        redact_paths=opts.redact_local_paths,
    )

    gps_included = bool(
        opts.include_gps
        and gps_result is not None
        and gps_result.status is MetadataStatus.PRESENT
        and gps_result.latitude is not None
        and gps_result.longitude is not None
    )

    styles = _build_styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="PIXELTRUTH Forensic Inspection Report",
        author="PIXELTRUTH",
    )
    usable_width = A4[0] - (32 * mm)
    story: list[object] = []
    included_sections: list[str] = []

    # Header block
    story.append(_p("PIXELTRUTH Forensic Inspection Report", styles["title"]))
    story.append(
        _p(
            "Local-first image metadata inspection and evidence summary. "
            "Observations and limitations only — not an authenticity verdict.",
            styles["subtitle"],
        )
    )

    gps_status_text = (
        "Included by explicit user selection"
        if gps_included
        else (
            "Requested for report, but no valid GPS coordinates were available"
            if opts.include_gps
            else "Excluded by default"
        )
    )
    meta_rows = [
        [_p("Report Field", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
        [_p("Report ID", styles["cell"]), _p(resolved_id, styles["mono"])],
        [_p("Generated (UTC)", styles["cell"]), _p(resolved_time, styles["cell"])],
        [_p("Subject filename", styles["cell"]), _p(display_name, styles["mono"])],
        [_p("Assessment rule-set", styles["cell"]), _p(resolved_assessment.rule_set_version, styles["mono"])],
        [
            _p("Path redaction", styles["cell"]),
            _p("Enabled (basename only)" if opts.redact_local_paths else "Disabled by user", styles["cell"]),
        ],
        [_p("GPS coordinates", styles["cell"]), _p(gps_status_text, styles["cell"])],
    ]
    story.append(_styled_table(meta_rows, [usable_width * 0.28, usable_width * 0.72]))
    story.append(Spacer(1, 8))

    # 1. Evidence Assessment
    if opts.include_assessment:
        included_sections.append("Evidence Assessment")
        story.append(_p("1. Evidence Assessment", styles["h2"]))
        story.append(
            _p(f"Outcome: {resolved_assessment.outcome.value}", styles["cell_bold"])
        )
        story.append(_p(resolved_assessment.outcome_explanation, styles["body"]))

        if resolved_assessment.findings:
            story.append(_p("Documented assessment observations", styles["cell_bold"]))
            for finding in resolved_assessment.findings:
                story.append(
                    _p(
                        f"{finding.title} [{finding.relevance}] — "
                        f"rule_id={finding.rule_id}, finding_id={finding.finding_id}, "
                        f"check_id={finding.check_id}, evaluation_id={finding.evaluation_id}",
                        styles["cell_bold"],
                    )
                )
                story.append(_p(f"Observed evidence: {finding.observed_evidence}", styles["cell"]))
                story.append(_p(f"Explanation: {finding.explanation}", styles["cell"]))
                story.append(_p(f"Possible interpretations: {finding.possible_interpretations}", styles["cell"]))
                story.append(_p(f"Limitations: {finding.limitations}", styles["cell"]))
                story.append(_p(f"Recommended next check: {finding.recommended_next_check}", styles["muted"]))
        else:
            story.append(
                _p("No findings were emitted by the registered assessment rules.", styles["muted"])
            )

        if resolved_assessment.evaluations:
            total_evals = len(resolved_assessment.evaluations)
            app_evals = sum(1 for e in resolved_assessment.evaluations if e.applicability == "APPLICABLE")
            eval_ok = sum(
                1 for e in resolved_assessment.evaluations
                if e.coverage_state in {"EVALUATED_WITH_FINDING", "EVALUATED_WITHOUT_FINDING"}
            )
            na_evals = sum(1 for e in resolved_assessment.evaluations if e.applicability == "NOT_APPLICABLE")
            ne_evals = sum(
                1 for e in resolved_assessment.evaluations
                if e.coverage_state == "NOT_EVALUABLE" and e.applicability != "NOT_APPLICABLE"
            )
            story.append(
                _p(
                    f"Rule evaluation coverage: {total_evals} total · {app_evals} applicable · "
                    f"{eval_ok} evaluated · {na_evals} not applicable · {ne_evals} not evaluated",
                    styles["cell_bold"],
                )
            )
            eval_rows = [
                [
                    _p("Evaluation ID", styles["cell_bold"]),
                    _p("Applicability", styles["cell_bold"]),
                    _p("Coverage", styles["cell_bold"]),
                    _p("Reason", styles["cell_bold"]),
                ]
            ]
            for ev in resolved_assessment.evaluations:
                app_str = ev.applicability.value if hasattr(ev.applicability, "value") else str(ev.applicability)
                cov_str = ev.coverage_state.value if hasattr(ev.coverage_state, "value") else str(ev.coverage_state)
                eval_rows.append(
                    [
                        _p(ev.evaluation_id, styles["mono"]),
                        _p(app_str, styles["cell"]),
                        _p(cov_str, styles["cell"]),
                        _p(ev.coverage_reason, styles["cell"]),
                    ]
                )
            story.append(
                _styled_table(
                    eval_rows,
                    [usable_width * 0.31, usable_width * 0.17, usable_width * 0.22, usable_width * 0.30],
                )
            )
            story.append(Spacer(1, 6))

    # 2. Image Properties & SHA-256
    if opts.include_properties:
        included_sections.append("Image Properties & SHA-256")
        props = inspection.properties
        story.append(_p("2. Image Properties and SHA-256 Fingerprint", styles["h2"]))
        prop_rows = [
            [_p("Property", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
            [_p("Filename", styles["cell"]), _p(display_name, styles["mono"])],
            [_p("Detected format / MIME", styles["cell"]), _p(f"{props.image_format} ({props.mime_type})", styles["cell"])],
            [_p("Dimensions", styles["cell"]), _p(f"{props.width} x {props.height} px", styles["cell"])],
            [_p("Aspect ratio / Resolution", styles["cell"]), _p(f"{props.aspect_ratio:.3f}:1 ({props.megapixels:.2f} MP)", styles["cell"])],
            [_p("File size", styles["cell"]), _p(f"{props.file_size_bytes:,} bytes", styles["cell"])],
            [_p("Colour mode / Bit depth", styles["cell"]), _p(f"{props.color_mode} / {props.bit_depth_per_channel}-bit" if props.bit_depth_per_channel else f"{props.color_mode} / Unavailable", styles["cell"])],
            [_p("Frames / Transparency", styles["cell"]), _p(f"{props.frame_count} frame(s) / {'Present' if props.has_transparency else 'Not detected'}", styles["cell"])],
            [_p("SHA-256 (original bytes)", styles["cell"]), _p(inspection.sha256, styles["mono"])],
        ]
        story.append(_styled_table(prop_rows, [usable_width * 0.30, usable_width * 0.70]))
        story.append(Spacer(1, 6))

    # 3. Metadata Observations
    if opts.include_metadata:
        included_sections.append("Metadata Observations")
        story.append(_p("3. Metadata Observations", styles["h2"]))
        if not inspection.metadata:
            story.append(_p("No metadata fields were provided for this inspection.", styles["muted"]))
        else:
            meta_table_rows = [
                [
                    _p("Source", styles["cell_bold"]),
                    _p("Field", styles["cell_bold"]),
                    _p("Status", styles["cell_bold"]),
                    _p("Value / Note", styles["cell_bold"]),
                ]
            ]
            for field in inspection.metadata:
                val_text = field.value if field.value is not None else "Not available"
                if field.note:
                    val_text = f"{val_text} ({field.note})"
                meta_table_rows.append(
                    [
                        _p(field.source or "Unknown", styles["cell"]),
                        _p(field.label, styles["cell"]),
                        _p(field.status.value, styles["cell"]),
                        _p(val_text, styles["cell"]),
                    ]
                )
            story.append(
                _styled_table(
                    meta_table_rows,
                    [usable_width * 0.12, usable_width * 0.28, usable_width * 0.16, usable_width * 0.44],
                )
            )
        story.append(Spacer(1, 6))

    # 4. Optional Analyses (ELA / Histogram / GPS)
    if opts.include_ela and ela_result is not None:
        included_sections.append("Error Level Analysis")
        story.append(_p("4. Error Level Analysis (ELA — Descriptive)", styles["h2"]))
        ela_rows = [
            [_p("Metric", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
            [_p("JPEG quality / Error scale", styles["cell"]), _p(f"Quality {ela_result.quality} / Scale x{ela_result.error_scale}", styles["cell"])],
            [_p("Processed dimensions", styles["cell"]), _p(f"{ela_result.width} x {ela_result.height} px", styles["cell"])],
            [_p("Mean RGB difference", styles["cell"]), _p(f"{ela_result.mean_absolute_difference:.3f}", styles["cell"])],
            [_p("Changed pixels / Max diff", styles["cell"]), _p(f"{ela_result.changed_pixel_percent:.1f}% / {ela_result.maximum_channel_difference}", styles["cell"])],
            [_p("Method", styles["cell"]), _p(ela_result.method, styles["cell"])],
            [_p("Limitations", styles["cell"]), _p(ela_result.limitations, styles["cell"])],
        ]
        story.append(_styled_table(ela_rows, [usable_width * 0.30, usable_width * 0.70]))
        story.append(Spacer(1, 6))

    if opts.include_histogram and histogram_result is not None:
        included_sections.append("RGB Histogram")
        story.append(_p("RGB Intensity Histogram (Descriptive)", styles["h2"]))
        hist_rows = [
            [_p("Metric", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
            [_p("Frame dimensions / Count", styles["cell"]), _p(f"{histogram_result.width} x {histogram_result.height} px / {histogram_result.frame_count} frame(s)", styles["cell"])],
            [_p("Decoded pixels counted", styles["cell"]), _p(f"{histogram_result.pixel_count:,}", styles["cell"])],
            [_p("Method", styles["cell"]), _p(histogram_result.method, styles["cell"])],
            [_p("Limitations", styles["cell"]), _p(histogram_result.limitations, styles["cell"])],
        ]
        story.append(_styled_table(hist_rows, [usable_width * 0.30, usable_width * 0.70]))
        story.append(Spacer(1, 6))

    if gps_included and gps_result is not None:
        included_sections.append("GPS Information")
        story.append(_p("GPS Coordinates (Explicitly Included)", styles["h2"]))
        gps_rows = [
            [_p("Field", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
            [_p("Latitude", styles["cell"]), _p(f"{gps_result.latitude:.6f}", styles["mono"])],
            [_p("Longitude", styles["cell"]), _p(f"{gps_result.longitude:.6f}", styles["mono"])],
        ]
        if gps_result.altitude_meters is not None:
            gps_rows.append([_p("Altitude", styles["cell"]), _p(f"{gps_result.altitude_meters:.1f} m", styles["mono"])])
        if gps_result.timestamp_utc:
            gps_rows.append([_p("GPS timestamp", styles["cell"]), _p(gps_result.timestamp_utc, styles["mono"])])
        story.append(_styled_table(gps_rows, [usable_width * 0.30, usable_width * 0.70]))
        story.append(Spacer(1, 6))

    if opts.include_malware_scan:
        included_sections.append("Malware & Security Analysis")
        story.append(_p("Malware and Security Analysis (ClamAV)", styles["h2"]))
        if malware_scan is None:
            story.append(
                _p(
                    "Malware scan result is unavailable. The file's malware status is unknown.",
                    styles["muted"],
                )
            )
        else:
            ms_rows = [
                [_p("Field", styles["cell_bold"]), _p("Value", styles["cell_bold"])],
                [_p("Scanner", styles["cell"]), _p(malware_scan.scanner_name, styles["cell"])],
                [_p("Scanner version", styles["cell"]), _p(malware_scan.scanner_version or "Unavailable", styles["mono"])],
                [_p("Signature DB version", styles["cell"]), _p(malware_scan.signature_database_version or "Unavailable", styles["mono"])],
                [_p("Database freshness", styles["cell"]), _p(malware_scan.database_freshness.value, styles["cell"])],
                [_p("Scan timestamp (UTC)", styles["cell"]), _p(malware_scan.scan_completed_at or malware_scan.scan_started_at or "Unavailable", styles["mono"])],
                [_p("Scan status", styles["cell"]), _p(malware_scan.scan_status.value, styles["mono"])],
                [_p("Detection count", styles["cell"]), _p(str(malware_scan.detection_count), styles["mono"])],
            ]
            if malware_scan.reason_code:
                ms_rows.append([_p("Reason code", styles["cell"]), _p(malware_scan.reason_code, styles["mono"])])
            story.append(_styled_table(ms_rows, [usable_width * 0.30, usable_width * 0.70]))
            story.append(Spacer(1, 4))

            if malware_scan.scan_status is MalwareScanOutcome.NO_KNOWN_THREAT:
                story.append(
                    _p(
                        "No known malware signatures were detected by the completed ClamAV scan. "
                        "This does not guarantee that the file is completely safe.",
                        styles["body"],
                    )
                )
            elif malware_scan.scan_status is MalwareScanOutcome.MALWARE_DETECTED:
                story.append(
                    _p(
                        "ClamAV detected known malware signature(s) in this file. Do not open or execute this file.",
                        styles["cell_bold"],
                    )
                )
                if malware_scan.detections:
                    det_rows = [
                        [
                            _p("Detection Name", styles["cell_bold"]),
                            _p("Category", styles["cell_bold"]),
                            _p("Verdict", styles["cell_bold"]),
                        ]
                    ]
                    for det in malware_scan.detections:
                        det_rows.append(
                            [
                                _p(det.detection_name, styles["mono"]),
                                _p(det.threat_category or "Unspecified", styles["cell"]),
                                _p(det.scanner_verdict, styles["mono"]),
                            ]
                        )
                    story.append(
                        _styled_table(
                            det_rows,
                            [usable_width * 0.56, usable_width * 0.24, usable_width * 0.20],
                        )
                    )
            else:
                story.append(
                    _p(
                        "The malware scan could not be completed reliably. The file's malware status is unknown.",
                        styles["body"],
                    )
                )

            for err in malware_scan.errors:
                story.append(_p(f"Error: {err}", styles["cell"]))
            for warn in malware_scan.warnings:
                story.append(_p(f"Warning: {warn}", styles["cell"]))
            for lim in malware_scan.limitations:
                story.append(_p(f"- {lim}", styles["muted"]))
        story.append(Spacer(1, 6))

    # 5. Coverage Limitations & Scientific Disclaimers
    included_sections.append("Limitations & Disclaimers")
    story.append(_p("Coverage Limitations and Scientific Disclaimers", styles["h2"]))
    for note in resolved_assessment.limitations:
        story.append(_p(f"- {note}", styles["body"]))
    if BOUNDARY_STATEMENT not in resolved_assessment.limitations:
        story.append(_p(f"- {BOUNDARY_STATEMENT}", styles["body"]))
    story.append(
        _p(
            "- Missing metadata, ELA residual patterns, RGB histogram shapes, and editing-software "
            "tags alone do not establish manipulation or prove authenticity.",
            styles["muted"],
        )
    )

    doc.build(story)
    return ReportResult(
        report_id=resolved_id,
        generated_at_utc=resolved_time,
        pdf_bytes=buffer.getvalue(),
        included_sections=tuple(included_sections),
        gps_included=gps_included,
        paths_redacted=opts.redact_local_paths,
        rule_set_version=resolved_assessment.rule_set_version,
        display_filename=display_name,
    )
