"""PIXELTRUTH Streamlit entry point for the Phase 0 project foundation."""

import streamlit as st


st.set_page_config(
    page_title="PIXELTRUTH",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("PIXELTRUTH")
st.subheader("Image Metadata Inspector & Digital Forensics Studio")
st.divider()

st.info(
    "The project foundation is ready. Image inspection and forensic features "
    "have not been implemented yet."
)
st.caption("Phase 0 scaffold — no image has been uploaded or processed.")
