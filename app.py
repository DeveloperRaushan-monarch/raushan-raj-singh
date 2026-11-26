"""PIXELTRUTH local-first image inspection and comparison interface."""

from io import BytesIO

import pandas as pd
import streamlit as st
from PIL import Image, ImageOps

from core.analysis import inspect_image
from core.comparison import compare_images
from core.gps import GPSResult, extract_gps
from core.models import Finding, ImageInspection, MetadataStatus
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


def _render_properties(inspection: ImageInspection) -> None:
    props = inspection.properties
    for warning in inspection.warnings:
        st.warning(warning)
    metrics = st.columns(3)
    metrics[0].metric("Format", props.image_format)
    metrics[1].metric("Dimensions", f"{props.width} × {props.height}")
    metrics[2].metric("File size", f"{props.file_size_bytes / (1024 * 1024):.2f} MB")
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
    rows = [
        {
            "Field": field.label,
            "Value": field.value if field.value is not None else "Not available",
            "Status": field.status.value,
            "Note": field.note or "",
        }
        for field in inspection.metadata
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


st.set_page_config(
    page_title="PIXELTRUTH — Image Inspection",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)
st.markdown(
    """
    <style>
      .stApp { background: #000000; color: #ffffff; }
      [data-testid="stHeader"] { background: #000000; }
      [data-testid="stMetric"] { background: #181818; border: 1px solid #303030; padding: 1rem; }
      code { font-family: "Source Code Pro", monospace; }
    </style>
    """,
    unsafe_allow_html=True,
)
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
        st.session_state.pop("pixeltruth_last_inspection", None)
        st.error(str(exc))
else:
    _clear_gps_state()

analysis_tab, metadata_tab, gps_tab, comparison_tab = st.tabs(
    ["Image Analysis", "Metadata & Findings", "GPS Intelligence", "Image Comparison"]
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
