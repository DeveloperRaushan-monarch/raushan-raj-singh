"""PIXELTRUTH local-first image inspection and comparison interface."""

import html
from io import BytesIO

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from PIL import Image, ImageOps

from core.analysis import inspect_image
from core.assessment_engine import assess_inspection
from core.assessment_models import AssessmentResult
from core.comparison import compare_images
from core.ela import ELAError, ELAResult, apply_exif_orientation, calculate_ela
from core.gps import GPSResult, extract_gps
from core.histogram import HistogramError, HistogramResult, calculate_rgb_histogram
from core.models import Finding, ImageInspection, MetadataStatus
from core.report import ReportOptions, ReportResult, generate_pdf_report, sanitize_display_filename
from utils.validators import ImageValidationError, MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS


def _render_findings(findings: tuple[Finding, ...]) -> None:
    if not findings:
        st.success("No metadata availability, validity, or consistency findings were returned by these checks.")
        return
    for finding in findings:
        with st.expander(f"{finding.title} · {finding.relevance}"):
            st.write("**Observed evidence**", finding.observed_evidence)
            st.write("**Explanation**", finding.explanation)
            st.write("**Possible interpretations**", finding.possible_interpretations)
            st.write("**Confidence limitations**", finding.confidence_limitations)
            st.write("**Recommended next check**", finding.recommended_next_check)


def _clear_gps_state() -> None:
    st.session_state.pop("pixeltruth_gps_result", None)
    st.session_state.pop("pixeltruth_gps_source_hash", None)


def _clear_ela_state() -> None:
    st.session_state.pop("pixeltruth_ela_result", None)
    st.session_state.pop("pixeltruth_ela_source_hash", None)
    st.session_state.pop("pixeltruth_ela_parameters", None)


def _clear_histogram_state() -> None:
    st.session_state.pop("pixeltruth_histogram_result", None)
    st.session_state.pop("pixeltruth_histogram_source_hash", None)


def _clear_report_state() -> None:
    st.session_state.pop("pixeltruth_report_result", None)
    st.session_state.pop("pixeltruth_report_source_hash", None)
    st.session_state.pop("pixeltruth_report_options", None)


def _render_properties(inspection: ImageInspection) -> None:
    props = inspection.properties
    for warning in inspection.warnings:
        st.warning(warning)
    row1 = st.columns(3)
    row1[0].metric("Format", props.image_format)
    row1[1].metric("Dimensions", f"{props.width} × {props.height}")
    row1[2].metric("File size", f"{props.file_size_bytes / (1024 * 1024):.2f} MB")
    row2 = st.columns(3)
    row2[0].metric("Colour mode", props.color_mode)
    row2[1].metric("Aspect ratio", f"{props.aspect_ratio:.3f}:1")
    row2[2].metric("Resolution", f"{props.megapixels:.2f} MP")
    rows = [
        ("Filename", props.filename),
        ("MIME type", props.mime_type),
        ("Aspect ratio", f"{props.aspect_ratio:.3f}:1"),
        ("Resolution", f"{props.megapixels:.2f} megapixels"),
        ("Colour mode", props.color_mode),
        ("Bit depth per channel", f"{props.bit_depth_per_channel}-bit" if props.bit_depth_per_channel else "Unavailable"),
        ("Frames", str(props.frame_count)),
        ("Transparency", "Present" if props.has_transparency else "Not detected"),
    ]
    st.dataframe(pd.DataFrame(rows, columns=["Property", "Value"]), hide_index=True, width="stretch")
    st.markdown("#### SHA-256 fingerprint")
    st.caption("Calculated from the original uploaded bytes. Matching hashes mean identical file contents.")
    st.code(inspection.sha256, language=None)


def _render_metadata(inspection: ImageInspection) -> None:
    for source, title in (("EXIF", "EXIF"), ("XMP", "XMP"), ("IPTC", "IPTC")):
        source_fields = [field for field in inspection.metadata if field.source == source]
        st.markdown(f"##### {title}")
        if source_fields:
            st.caption(f"{len(source_fields)} inspected field(s)")
        if not source_fields:
            st.info(f"No {title} fields are available for this image.")
            continue
        packet_key = "xmp" if source == "XMP" else "iptc" if source == "IPTC" else None
        packet = next((field for field in source_fields if field.key == packet_key), None) if packet_key else None
        if packet is not None and packet.status is MetadataStatus.MISSING:
            st.info(f"No {title} metadata was found in the supported storage location.")
        elif packet is not None and packet.status is MetadataStatus.UNSUPPORTED:
            st.info(f"{title} extraction is unsupported for this image format.")
        rows = [
            {
                "Field": field.label,
                "Value": field.value if field.value is not None else "Not available",
                "Status": field.status.value,
                "Note": field.note or "",
            }
            for field in source_fields
        ]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.caption("Missing metadata is not evidence that information was removed.")


def _render_gps(inspection: ImageInspection, file_bytes: bytes) -> None:
    st.write("Coordinates can reveal where a photograph was taken. They stay hidden until you choose to reveal them.")
    digest = inspection.sha256
    if st.session_state.get("pixeltruth_gps_source_hash") != digest:
        _clear_gps_state()

    result: GPSResult | None = st.session_state.get("pixeltruth_gps_result")
    if result is None:
        if st.button("Reveal GPS information", type="secondary", key="reveal_gps"):
            st.session_state["pixeltruth_gps_result"] = extract_gps(
                file_bytes, inspection.properties.image_format
            )
            st.session_state["pixeltruth_gps_source_hash"] = digest
            st.rerun()
        st.info("GPS values have not been read for display.")
        return

    if result.status is MetadataStatus.PRESENT:
        st.write(f"**Latitude:** {result.latitude:.6f}")
        st.write(f"**Longitude:** {result.longitude:.6f}")
        if result.altitude_meters is not None:
            st.write(f"**Altitude:** {result.altitude_meters:.1f} m")
        if result.timestamp_utc:
            st.write(f"**GPS timestamp:** {result.timestamp_utc}")
    else:
        st.info(result.note or result.status.value)

    if st.button("Clear displayed GPS information", key="clear_gps"):
        _clear_gps_state()
        st.rerun()


def _render_comparison() -> None:
    st.write("Compare two validated images. Similarity is descriptive and does not establish common origin or authenticity.")
    left, right = st.columns(2)
    with left:
        reference_file = st.file_uploader(
            "Image A · Reference",
            type=list(SUPPORTED_EXTENSIONS),
            max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
            key="comparison_reference",
        )
    with right:
        suspect_file = st.file_uploader(
            "Image B · Suspect",
            type=list(SUPPORTED_EXTENSIONS),
            max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
            key="comparison_suspect",
        )
    if reference_file is None or suspect_file is None:
        st.info("Choose both images to compare their properties, metadata, hashes, and supported pixel indicator.")
        return

    try:
        result = compare_images(
            reference_file.getvalue(), reference_file.name,
            suspect_file.getvalue(), suspect_file.name,
        )
    except ImageValidationError as exc:
        st.error(str(exc))
        return

    st.markdown("#### Side-by-side image properties")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**Image A · {result.reference.properties.filename}**")
        st.image(reference_file.getvalue(), width="stretch")
    with c2:
        st.markdown(f"**Image B · {result.suspect.properties.filename}**")
        st.image(suspect_file.getvalue(), width="stretch")

    st.markdown("#### Comparison breakdown")
    st.dataframe(
        pd.DataFrame(
            [
                {"Metric": metric.label, "Image A": metric.reference_value, "Image B": metric.suspect_value,
                 "Status": "Match" if metric.matches else "Different"}
                for metric in result.metrics
            ]
        ),
        hide_index=True,
        width="stretch",
    )
    if result.sampled_pixel_similarity is None:
        st.info(result.similarity_note)
    else:
        st.metric("Sampled pixel similarity indicator", f"{result.sampled_pixel_similarity:.3f}")
        st.caption(result.similarity_note)
    st.caption("Different hashes do not necessarily indicate different visual content. Matching hashes indicate identical file bytes.")

    st.markdown("#### Metadata differences")
    if result.metadata_differences:
        st.dataframe(
            pd.DataFrame(
                [
                    {"Field": item.label, "Image A": item.reference_value, "Image B": item.suspect_value}
                    for item in result.metadata_differences
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No differences were found among the metadata fields inspected by this phase.")


def _render_ela(inspection: ImageInspection | None, file_bytes: bytes | None) -> None:
    st.write("Error Level Analysis compares decoded JPEG pixels with one recompressed copy.")
    if inspection is None or file_bytes is None:
        st.info("Select a valid image before running ELA.")
        return

    digest = inspection.sha256
    if st.session_state.get("pixeltruth_ela_source_hash") not in {None, digest}:
        _clear_ela_state()
    if inspection.properties.image_format != "JPEG":
        _clear_ela_state()
        st.info(f"ELA applies to JPEG images only. This file is {inspection.properties.image_format}; ELA was not run.")
        return

    quality = st.slider("JPEG recompression quality", min_value=50, max_value=100, value=90, step=5, key="ela_quality")
    error_scale = st.slider("Error scale", min_value=1, max_value=20, value=10, step=1, key="ela_error_scale")
    parameters = (quality, error_scale)
    if st.session_state.get("pixeltruth_ela_parameters") not in {None, parameters}:
        _clear_ela_state()

    st.caption(f"Quality: {quality} · Error scale: ×{error_scale} · Maximum processed size: 20 megapixels")
    if st.button("Run ELA", type="secondary", key="run_ela"):
        _clear_ela_state()
        try:
            result = calculate_ela(file_bytes, quality=quality, error_scale=error_scale)
        except (ELAError, ImageValidationError) as exc:
            st.error(str(exc))
        else:
            st.session_state["pixeltruth_ela_result"] = result
            st.session_state["pixeltruth_ela_source_hash"] = digest
            st.session_state["pixeltruth_ela_parameters"] = parameters
            st.rerun()

    result: ELAResult | None = st.session_state.get("pixeltruth_ela_result")
    if result is None:
        st.info("ELA has not been run for this image and these settings.")
        return

    st.markdown("#### Original and recompression residual")
    original_column, residual_column = st.columns(2)
    with original_column:
        try:
            with Image.open(BytesIO(file_bytes)) as source_image:
                oriented_preview = apply_exif_orientation(source_image.copy())
                st.image(oriented_preview, caption="Original JPEG (EXIF orientation applied)", width="stretch")
        except (OSError, ValueError):
            st.warning("The original preview could not be rendered. The ELA result remains available.")
    with residual_column:
        st.image(result.residual_png, caption="Amplified ELA residual", width="stretch")
    metric_columns = st.columns(3)
    metric_columns[0].metric("Mean RGB difference (0–255)", f"{result.mean_absolute_difference:.3f}")
    metric_columns[1].metric("Pixels with residual", f"{result.changed_pixel_percent:.1f}%")
    metric_columns[2].metric("Maximum channel difference", str(result.maximum_channel_difference))
    st.caption(result.method)
    how_col, lim_col = st.columns(2, gap="medium")
    with how_col:
        with st.container(border=True):
            st.markdown("#### How it works")
            st.write("The decoded RGB image is saved once as JPEG at the selected quality. The absolute pixel difference is amplified by the selected scale for viewing.")
    with lim_col:
        with st.container(border=True):
            st.markdown("#### Analytical limitations")
            st.write(result.limitations)


def _histogram_figure(
    series: tuple[tuple[str, tuple[int, ...], str, str], ...],
    *,
    legend: bool,
    y_axis_title: str = "Pixel count",
) -> go.Figure:
    figure = go.Figure()
    intensity_values = list(range(256))
    for label, counts, color, dash in series:
        figure.add_trace(
            go.Scatter(
                x=intensity_values,
                y=counts,
                mode="lines",
                name=label,
                line={"color": color, "dash": dash, "width": 2},
                hovertemplate="Intensity %{x}<br>Count %{y:,}<extra>%{fullData.name}</extra>",
            )
        )
    figure.update_layout(
        height=300,
        margin={"l": 48, "r": 16, "t": 20, "b": 48},
        paper_bgcolor="#101010",
        plot_bgcolor="#101010",
        font={"color": "#eeeeee"},
        showlegend=legend,
        legend={"orientation": "h", "y": 1.12, "x": 0},
    )
    figure.update_xaxes(
        title="Intensity (0–255)",
        range=[0, 255],
        dtick=32,
        gridcolor="#353535",
        zerolinecolor="#555555",
    )
    figure.update_yaxes(
        title=y_axis_title,
        rangemode="tozero",
        gridcolor="#353535",
        zerolinecolor="#555555",
    )
    return figure


def _render_histogram(inspection: ImageInspection | None, file_bytes: bytes | None) -> None:
    st.write("View the distribution of decoded pixel intensities across red, green, and blue channels.")
    if inspection is None or file_bytes is None:
        _clear_histogram_state()
        st.info("Select a valid image before calculating its RGB histogram.")
        return

    digest = inspection.sha256
    if st.session_state.get("pixeltruth_histogram_source_hash") != digest:
        _clear_histogram_state()

    result: HistogramResult | None = st.session_state.get("pixeltruth_histogram_result")
    if result is None:
        st.caption("The combined view pools all three channel counts. Separate views use labeled monochrome line styles.")
        if st.button("Calculate RGB histogram", type="secondary", key="calculate_rgb_histogram"):
            try:
                result = calculate_rgb_histogram(file_bytes, inspection.properties.filename)
            except (HistogramError, ImageValidationError) as exc:
                st.error(str(exc))
                return
            st.session_state["pixeltruth_histogram_result"] = result
            st.session_state["pixeltruth_histogram_source_hash"] = digest
            st.rerun()
        st.info("Histogram analysis has not been run for this image.")
        return

    if len(set(result.frame_dimensions)) == 1:
        dimensions_description = f"{result.width} × {result.height} pixels per frame"
    else:
        dimensions_description = "Frame dimensions vary"
    st.caption(
        f"{dimensions_description} · {result.frame_count} frame(s) · "
        f"{result.pixel_count:,} decoded pixels"
    )
    st.markdown("#### Combined RGB intensity distribution")
    combined_series = (("All RGB channel values", result.combined, "#dddddd", "solid"),)
    st.plotly_chart(
        _histogram_figure(combined_series, legend=True, y_axis_title="Channel-value count"),
        width="stretch",
        key="combined_rgb_histogram",
    )

    st.markdown("#### Individual channel distributions")
    channel_columns = st.columns(3)
    for column, (label, counts, dash) in zip(
        channel_columns,
        (("Red", result.red, "solid"), ("Green", result.green, "dash"), ("Blue", result.blue, "dot")),
    ):
        with column:
            st.markdown(f"**{label} channel**")
            figure = _histogram_figure(((label, counts, "#dddddd", dash),), legend=False)
            st.plotly_chart(figure, width="stretch", key=f"{label.lower()}_rgb_histogram")

    st.caption(result.method)
    st.markdown("#### Analytical limitations")
    st.write(result.limitations)


def _render_assessment(inspection: ImageInspection | None) -> None:
    if inspection is None:
        st.info("Select a valid image above to view the evidence assessment summary.")
        return

    result: AssessmentResult = assess_inspection(inspection)
    st.markdown(f"#### Assessment outcome: {result.outcome.value}")
    st.write(result.outcome_explanation)
    st.caption(f"Rule-set version: {result.rule_set_version}")

    st.markdown("#### Documented assessment observations")
    if not result.findings:
        st.info("No findings were emitted by the registered assessment rules.")
    else:
        for finding in result.findings:
            with st.expander(f"{finding.title} · {finding.relevance}"):
                st.write("**Rule ID**", finding.rule_id)
                st.write("**Finding ID**", finding.finding_id)
                st.write("**Check ID**", finding.check_id)
                st.write("**Evaluation ID**", finding.evaluation_id)
                st.write("**Observed evidence**", finding.observed_evidence)
                st.write("**Explanation**", finding.explanation)
                st.write("**Possible interpretations**", finding.possible_interpretations)
                st.write("**Limitations**", finding.limitations)
                st.write("**Recommended next check**", finding.recommended_next_check)

    st.markdown("#### Rule evaluation coverage")
    coverage_rows = [
        {
            "Rule": ev.rule_id,
            "Evaluation": ev.evaluation_id,
            "Check": ev.check_id,
            "Applicability": ev.applicability,
            "Coverage state": ev.coverage_state,
            "Reason": ev.coverage_reason,
            "Findings": ", ".join(ev.finding_ids) if ev.finding_ids else "None",
        }
        for ev in result.evaluations
    ]
    st.dataframe(pd.DataFrame(coverage_rows), hide_index=True, width="stretch")

    st.markdown("#### Limitations and scope")
    for note in result.limitations:
        st.write(f"- {note}")


def _render_reports(inspection: ImageInspection | None) -> None:
    st.write("Configure sections and privacy defaults to generate a monochrome A4 PDF inspection report.")
    if inspection is None:
        _clear_report_state()
        st.info("Select a valid image above to configure and generate a PDF report.")
        return

    digest = inspection.sha256
    if st.session_state.get("pixeltruth_report_source_hash") not in {None, digest}:
        _clear_report_state()

    ela_result: ELAResult | None = (
        st.session_state.get("pixeltruth_ela_result")
        if st.session_state.get("pixeltruth_ela_source_hash") == digest
        else None
    )
    histogram_result: HistogramResult | None = (
        st.session_state.get("pixeltruth_histogram_result")
        if st.session_state.get("pixeltruth_histogram_source_hash") == digest
        else None
    )
    gps_result: GPSResult | None = (
        st.session_state.get("pixeltruth_gps_result")
        if st.session_state.get("pixeltruth_gps_source_hash") == digest
        else None
    )
    gps_available = gps_result is not None and gps_result.status is MetadataStatus.PRESENT

    left_col, right_col = st.columns([1, 1.2], gap="large")
    with left_col:
        st.markdown("#### Report sections")
        include_assessment = st.checkbox("Evidence Assessment & provenance", value=True, key="report_include_assessment")
        include_properties = st.checkbox("Image properties & SHA-256", value=True, key="report_include_properties")
        include_metadata = st.checkbox("Metadata observations", value=True, key="report_include_metadata")
        include_ela = st.checkbox(
            "Error Level Analysis summary",
            value=False,
            disabled=ela_result is None,
            key="report_include_ela",
        )
        include_histogram = st.checkbox(
            "RGB histogram summary",
            value=False,
            disabled=histogram_result is None,
            key="report_include_histogram",
        )

        st.markdown("#### Privacy options")
        redact_local_paths = st.checkbox(
            "Redact local workstation paths",
            value=True,
            key="report_redact_paths",
        )
        include_gps = st.checkbox(
            "Include GPS coordinates in PDF",
            value=False,
            disabled=not gps_available,
            key="report_include_gps",
        )
        if include_gps and gps_available:
            st.warning("GPS privacy: Coordinates will be included in the generated PDF by explicit selection.")
        else:
            st.info("GPS privacy: GPS coordinates are excluded from the report by default.")

    options = ReportOptions(
        include_properties=include_properties,
        include_metadata=include_metadata,
        include_assessment=include_assessment,
        include_ela=include_ela and ela_result is not None,
        include_histogram=include_histogram and histogram_result is not None,
        include_gps=include_gps and gps_available,
        redact_local_paths=redact_local_paths,
    )
    if st.session_state.get("pixeltruth_report_options") not in {None, options}:
        _clear_report_state()

    assessment = assess_inspection(inspection)
    preview_name = html.escape(
        sanitize_display_filename(
            inspection.properties.filename,
            redact_paths=options.redact_local_paths,
        )
    )
    gps_preview_note = (
        "Included by explicit user selection"
        if options.include_gps
        else "Excluded by default"
    )
    with right_col:
        st.markdown("#### Printable report summary preview")
        st.markdown(
            f"""
            <div style="background:#F5F5F5; color:#111111; border:1px solid #CCCCCC; padding:1.25rem; border-radius:6px;">
              <div style="font-size:0.75rem; letter-spacing:0.06em; text-transform:uppercase; color:#555555;">PIXELTRUTH FORENSIC REPORT (PREVIEW)</div>
              <div style="font-size:1.1rem; font-weight:600; margin:0.25rem 0 0.75rem 0; border-bottom:1px solid #CCCCCC; padding-bottom:0.5rem;">Digital Image Inspection</div>
              <div style="font-size:0.875rem; line-height:1.6;">
                <strong>Subject:</strong> <code>{preview_name}</code><br/>
                <strong>Assessment outcome:</strong> <strong>{assessment.outcome.value}</strong> ({assessment.rule_set_version})<br/>
                <strong>SHA-256:</strong> <code style="word-break:break-all;">{inspection.sha256}</code><br/>
                <strong>GPS coordinates:</strong> {gps_preview_note}
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with left_col:
        if st.button("Generate PDF report", type="primary", key="generate_pdf_report"):
            report_result = generate_pdf_report(
                inspection,
                assessment=assessment,
                options=options,
                ela_result=ela_result if options.include_ela else None,
                histogram_result=histogram_result if options.include_histogram else None,
                gps_result=gps_result if options.include_gps else None,
            )
            st.session_state["pixeltruth_report_result"] = report_result
            st.session_state["pixeltruth_report_source_hash"] = digest
            st.session_state["pixeltruth_report_options"] = options
            st.rerun()

        cached_report: ReportResult | None = st.session_state.get("pixeltruth_report_result")
        if cached_report is not None:
            st.caption(f"Report ID: {cached_report.report_id} · Generated: {cached_report.generated_at_utc}")
            st.download_button(
                "Download PDF report",
                data=cached_report.pdf_bytes,
                file_name=f"pixeltruth_report_{digest[:12]}.pdf",
                mime="application/pdf",
                key="download_pdf_report",
            )


st.set_page_config(
    page_title="PIXELTRUTH — Image Inspection",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)
st.markdown(
    """
    <style>
      .stApp { background: #000000; color: #FFFFFF; font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      [data-testid="stHeader"] { background: #000000; }
      [data-testid="stSidebar"] { background: #111111; border-right: 1px solid #303030; }
      [data-testid="stMetric"] { background: #181818; border: 1px solid #303030; border-radius: 6px; padding: 1rem; }
      [data-testid="stFileUploaderDropzone"] { background: #181818; border: 1px dashed #303030; border-radius: 6px; }
      [data-testid="stExpander"] { background: #181818; border: 1px solid #303030; border-radius: 6px; }
      [data-testid="stAlert"] { background: #181818; border: 1px solid #303030; color: #FFFFFF; }
      [data-testid="stTabs"] button[role="tab"] { color: #B3B3B3; border-radius: 4px 4px 0 0; }
      [data-testid="stTabs"] button[role="tab"][aria-selected="true"] { color: #FFFFFF; background: #222222; border-bottom-color: #FFFFFF; }
      .stButton > button[kind="primary"] { background: #FFFFFF; color: #111111; border: 1px solid #FFFFFF; border-radius: 4px; }
      .stButton > button[kind="secondary"] { background: #181818; color: #FFFFFF; border: 1px solid #303030; border-radius: 4px; }
      code { font-family: "Source Code Pro", ui-monospace, SFMono-Regular, Menlo, monospace; }
    </style>
    """,
    unsafe_allow_html=True,
)
with st.sidebar:
    st.markdown("### PIXELTRUTH")
    st.caption("Local Workstation Mode")
    st.write("Zero external network uploads. All image inspection, metadata parsing, assessment, and PDF generation run locally in memory.")
    st.divider()
    st.markdown("#### About Project")
    st.write("PIXELTRUTH summarizes observable file, metadata, and pixel evidence alongside analytical limitations. It does not determine or certify whether an image is authentic, real, or fake.")

st.title("PIXELTRUTH")
st.caption("IMAGE METADATA INSPECTOR & DIGITAL FORENSICS STUDIO")
st.write("Local-first inspection with clear limits on what metadata can establish.")

uploaded = st.file_uploader(
    "Choose an image for analysis",
    type=list(SUPPORTED_EXTENSIONS),
    max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
    help="JPEG, PNG, WEBP, TIFF, BMP, or GIF. File contents are checked independently of the filename extension.",
)

inspection = None
file_bytes = None
if uploaded is not None:
    file_bytes = uploaded.getvalue()
    try:
        inspection = inspect_image(file_bytes, uploaded.name)
        st.session_state["pixeltruth_last_inspection"] = inspection
    except ImageValidationError as exc:
        _clear_gps_state()
        _clear_ela_state()
        _clear_histogram_state()
        _clear_report_state()
        st.session_state.pop("pixeltruth_last_inspection", None)
        st.error(str(exc))
else:
    _clear_gps_state()
    _clear_ela_state()
    _clear_histogram_state()
    _clear_report_state()

status_text = (
    f"Active: {html.escape(sanitize_display_filename(inspection.properties.filename))}"
    if inspection is not None
    else "Status: Awaiting image input"
)
st.markdown(
    f'<div style="display:inline-block; background:#111111; border:1px solid #303030; border-radius:4px; padding:0.35rem 0.75rem; font-family:monospace; font-size:0.8rem; color:#B3B3B3; margin-bottom:0.5rem;">{status_text}</div>',
    unsafe_allow_html=True,
)

analysis_tab, metadata_tab, gps_tab, comparison_tab, ela_tab, histogram_tab, assessment_tab, report_tab = st.tabs(
    [
        "Image Analysis",
        "Metadata & Findings",
        "GPS Intelligence",
        "Image Comparison",
        "Error Level Analysis",
        "RGB Histogram",
        "Evidence Assessment",
        "Forensic Reports",
    ]
)
with analysis_tab:
    if inspection is None or file_bytes is None:
        st.info("Select an image above to inspect its properties and SHA-256 fingerprint.")
    else:
        preview_column, details_column = st.columns([1, 1.25], gap="large")
        with preview_column:
            st.markdown("#### Image preview")
            try:
                with Image.open(BytesIO(file_bytes)) as source_image:
                    preview = ImageOps.exif_transpose(source_image.copy())
                    preview.thumbnail((960, 640))
                    st.image(preview, caption=inspection.properties.filename, width="stretch")
            except (OSError, ValueError):
                st.warning("The preview could not be rendered. Validated properties remain available.")
        with details_column:
            _render_properties(inspection)

with metadata_tab:
    if inspection is None:
        st.info("Select a valid image to inspect metadata.")
    else:
        st.markdown("#### Metadata fields")
        _render_metadata(inspection)
        st.markdown("#### Metadata integrity and consistency findings")
        _render_findings(inspection.findings)

with gps_tab:
    if inspection is None or file_bytes is None:
        st.info("Select a valid image before requesting GPS information.")
    else:
        _render_gps(inspection, file_bytes)

with comparison_tab:
    _render_comparison()

with ela_tab:
    _render_ela(inspection, file_bytes)

with histogram_tab:
    _render_histogram(inspection, file_bytes)

with assessment_tab:
    _render_assessment(inspection)

with report_tab:
    _render_reports(inspection)
