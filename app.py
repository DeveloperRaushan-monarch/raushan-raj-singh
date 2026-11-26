"""PIXELTRUTH Streamlit application entry point."""

from io import BytesIO

import pandas as pd
import streamlit as st
from PIL import Image, ImageOps

from core.analysis import inspect_image
from core.models import ImageInspection
from utils.validators import ImageValidationError, MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS


st.set_page_config(
    page_title="PIXELTRUTH — Image Analysis",
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
      div[data-testid="stAlert"] { border-radius: 4px; }
      code { font-family: "Source Code Pro", monospace; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("PIXELTRUTH")
st.caption("IMAGE METADATA INSPECTOR & DIGITAL FORENSICS STUDIO")
st.markdown("### Image Analysis")
st.write("Inspect file properties, available EXIF fields, and the file's SHA-256 fingerprint.")
st.caption("Phase 1 supports image inspection only. Metadata findings and forensic assessments are not yet implemented.")

uploaded = st.file_uploader(
    "Choose an image",
    type=list(SUPPORTED_EXTENSIONS),
    accept_multiple_files=False,
    max_upload_size=MAX_UPLOAD_BYTES // (1024 * 1024),
    help="JPEG, PNG, WEBP, TIFF, BMP, or GIF. The content is checked independently of its filename extension.",
)

if uploaded is None:
    st.info("Select a supported image to inspect it in this session.")
    st.stop()

file_bytes = uploaded.getvalue()
try:
    result: ImageInspection = inspect_image(file_bytes, uploaded.name)
except ImageValidationError as exc:
    st.session_state.pop("pixeltruth_last_inspection", None)
    st.error(str(exc))
    st.stop()

st.session_state["pixeltruth_last_inspection"] = result
properties = result.properties

for warning in result.warnings:
    st.warning(warning)

preview_column, details_column = st.columns([1, 1.25], gap="large")
with preview_column:
    st.markdown("#### Image preview")
    try:
        with Image.open(BytesIO(file_bytes)) as source_image:
            preview = ImageOps.exif_transpose(source_image.copy())
            preview.thumbnail((960, 640))
            st.image(preview, caption=properties.filename, use_container_width=True)
    except (OSError, ValueError):
        st.warning("The image preview could not be rendered. Validated properties remain available.")

with details_column:
    st.markdown("#### File properties")
    metric_columns = st.columns(3)
    metric_columns[0].metric("Format", properties.image_format)
    metric_columns[1].metric("Dimensions", f"{properties.width} × {properties.height}")
    metric_columns[2].metric("File size", f"{properties.file_size_bytes / (1024 * 1024):.2f} MB")

    property_rows = [
        ("Filename", properties.filename),
        ("MIME type", properties.mime_type),
        ("Aspect ratio", f"{properties.aspect_ratio:.3f}:1"),
        ("Resolution", f"{properties.megapixels:.2f} megapixels"),
        ("Colour mode", properties.color_mode),
        (
            "Bit depth per channel",
            f"{properties.bit_depth_per_channel}-bit" if properties.bit_depth_per_channel else "Unavailable",
        ),
        ("Frames", str(properties.frame_count)),
        ("Transparency", "Present" if properties.has_transparency else "Not detected"),
    ]
    st.dataframe(
        pd.DataFrame(property_rows, columns=["Property", "Value"]),
        hide_index=True,
        use_container_width=True,
    )

st.markdown("#### SHA-256 fingerprint")
st.caption("Calculated from the original uploaded file bytes. Matching hashes mean the file contents are identical.")
st.code(result.sha256, language=None)

st.markdown("#### Metadata fields")
metadata_rows = [
    {
        "Field": field.label,
        "Value": field.value if field.value is not None else "Not available",
        "Status": field.status.value,
        "Note": field.note or "",
    }
    for field in result.metadata
]
st.dataframe(pd.DataFrame(metadata_rows), hide_index=True, use_container_width=True)
st.caption("Missing metadata is not evidence that information was removed. GPS details are not displayed in Phase 1.")
