"""Focused, local AppTest coverage for the supported Streamlit workflow."""

from fractions import Fraction
from io import BytesIO
from pathlib import Path

from PIL import Image
from streamlit.testing.v1 import AppTest


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
APPTEST_TIMEOUT_SECONDS = 8


def make_png(color: str, size: tuple[int, int] = (12, 8)) -> bytes:
    output = BytesIO()
    Image.new("RGB", size, color).save(output, format="PNG")
    return output.getvalue()


def make_gps_jpeg() -> bytes:
    exif = Image.Exif()
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
    }
    output = BytesIO()
    Image.new("RGB", (12, 8), "white").save(output, format="JPEG", exif=exif)
    return output.getvalue()


def make_jpeg(color: str) -> bytes:
    output = BytesIO()
    Image.new("RGB", (12, 8), color).save(output, format="JPEG", quality=95)
    return output.getvalue()


def start_app() -> AppTest:
    app = AppTest.from_file(APP_PATH, default_timeout=APPTEST_TIMEOUT_SECONDS)
    app.run(timeout=APPTEST_TIMEOUT_SECONDS)
    assert not app.exception
    return app


def run_app(app: AppTest) -> None:
    app.run(timeout=APPTEST_TIMEOUT_SECONDS)
    assert not app.exception


def test_home_page_renders_without_exceptions():
    app = start_app()

    assert [item.value for item in app.title] == ["PIXELTRUTH"]
    assert [tab.label for tab in app.tabs] == [
        "Image Analysis",
        "Metadata & Findings",
        "GPS Intelligence",
        "Image Comparison",
        "Error Level Analysis",
        "RGB Histogram",
        "Evidence Assessment",
        "Forensic Reports",
    ]
    assert len(app.file_uploader) == 3
    assert any("Select an image above" in item.value for item in app.tabs[0].info)
    assert any("Select a valid image to inspect metadata" in item.value for item in app.tabs[1].info)
    assert any("Select a valid image before requesting GPS" in item.value for item in app.tabs[2].info)
    assert len(app.tabs[3].file_uploader) == 2
    assert any("Select a valid image before running ELA" in item.value for item in app.tabs[4].info)
    assert any("Select a valid image before calculating its RGB histogram" in item.value for item in app.tabs[5].info)


def test_valid_image_upload_renders_inspection_and_metadata_sections():
    app = start_app()
    app.file_uploader[0].set_value(("sample.png", make_png("white"), "image/png"))
    run_app(app)

    assert any(metric.label == "Format" and metric.value == "PNG" for metric in app.metric)
    assert len(app.image) == 1
    metadata_headings = [item.value for item in app.tabs[1].markdown]
    assert "##### EXIF" in metadata_headings
    assert "##### XMP" in metadata_headings
    assert "##### IPTC" in metadata_headings


def test_invalid_image_upload_shows_safe_error():
    app = start_app()
    app.file_uploader[0].set_value(("broken.png", b"not an image", "image/png"))
    run_app(app)

    assert len(app.error) == 1
    assert "not a supported, fully decodable image" in app.error[0].value
    assert not app.exception


def test_gps_stays_hidden_until_revealed_and_can_be_cleared():
    app = start_app()
    app.file_uploader[0].set_value(("synthetic-location.jpg", make_gps_jpeg(), "image/jpeg"))
    run_app(app)

    assert "pixeltruth_gps_result" not in app.session_state
    assert any(button.label == "Reveal GPS information" for button in app.button)
    assert not any("Latitude" in item.value or "Longitude" in item.value for item in app.markdown)

    next(button for button in app.button if button.label == "Reveal GPS information").click()
    run_app(app)
    assert "pixeltruth_gps_result" in app.session_state
    assert any("Latitude" in item.value for item in app.markdown)
    assert any("Longitude" in item.value for item in app.markdown)

    next(button for button in app.button if button.label == "Clear displayed GPS information").click()
    run_app(app)
    assert "pixeltruth_gps_result" not in app.session_state
    assert not any("Latitude" in item.value or "Longitude" in item.value for item in app.markdown)


def test_removing_main_upload_clears_revealed_gps_session_state():
    app = start_app()
    app.file_uploader[0].set_value(("synthetic-location.jpg", make_gps_jpeg(), "image/jpeg"))
    run_app(app)
    next(button for button in app.button if button.label == "Reveal GPS information").click()
    run_app(app)
    assert "pixeltruth_gps_result" in app.session_state

    app.file_uploader[0].clear()
    run_app(app)
    assert "pixeltruth_gps_result" not in app.session_state
    assert "pixeltruth_gps_source_hash" not in app.session_state


def test_comparison_controls_work_with_two_images():
    app = start_app()
    comparison_tab = app.tabs[3]
    assert len(comparison_tab.file_uploader) == 2
    comparison_tab.file_uploader[0].set_value(("reference.png", make_png("white"), "image/png"))
    comparison_tab.file_uploader[1].set_value(("candidate.png", make_png("black"), "image/png"))
    run_app(app)

    assert any(metric.label == "Sampled pixel similarity indicator" for metric in app.metric)
    assert len(app.image) == 2
    assert not app.error


def test_ela_is_explicit_and_jpeg_only():
    app = start_app()
    app.file_uploader[0].set_value(("sample.png", make_png("white"), "image/png"))
    run_app(app)
    assert any("ELA applies to JPEG images only" in item.value for item in app.tabs[4].info)
    assert not any(button.label == "Run ELA" for button in app.button)

    app.file_uploader[0].set_value(("sample.jpg", make_jpeg("white"), "image/jpeg"))
    run_app(app)
    assert any(slider.label == "JPEG recompression quality" for slider in app.slider)
    assert any(slider.label == "Error scale" for slider in app.slider)
    assert any(button.label == "Run ELA" for button in app.button)
    assert "pixeltruth_ela_result" not in app.session_state

    next(button for button in app.button if button.label == "Run ELA").click()
    run_app(app)
    assert "pixeltruth_ela_result" in app.session_state
    next(slider for slider in app.slider if slider.label == "JPEG recompression quality").set_value(85)
    run_app(app)
    assert "pixeltruth_ela_result" not in app.session_state
    assert not any(metric.label == "Mean RGB difference (0–255)" for metric in app.metric)

    next(button for button in app.button if button.label == "Run ELA").click()
    run_app(app)
    assert "pixeltruth_ela_result" in app.session_state
    next(slider for slider in app.slider if slider.label == "Error scale").set_value(5)
    run_app(app)
    assert "pixeltruth_ela_result" not in app.session_state

    next(button for button in app.button if button.label == "Run ELA").click()
    run_app(app)
    assert "pixeltruth_ela_result" in app.session_state
    app.file_uploader[0].set_value(("different.jpg", make_jpeg("black"), "image/jpeg"))
    run_app(app)
    assert "pixeltruth_ela_result" not in app.session_state
    assert not any(metric.label == "Mean RGB difference (0–255)" for metric in app.metric)

    next(button for button in app.button if button.label == "Run ELA").click()
    run_app(app)
    assert "pixeltruth_ela_result" in app.session_state
    app.file_uploader[0].clear()
    run_app(app)
    assert "pixeltruth_ela_result" not in app.session_state
    assert "pixeltruth_ela_source_hash" not in app.session_state

    app.file_uploader[0].set_value(("sample.png", make_png("white"), "image/png"))
    run_app(app)
    assert "pixeltruth_ela_result" not in app.session_state
    assert any("ELA applies to JPEG images only" in item.value for item in app.tabs[4].info)


def test_rgb_histogram_is_opt_in_and_uses_current_upload():
    app = start_app()
    app.file_uploader[0].set_value(("sample.png", make_png("white"), "image/png"))
    run_app(app)

    histogram_tab = app.tabs[5]
    assert "pixeltruth_histogram_result" not in app.session_state
    assert any(button.label == "Calculate RGB histogram" for button in histogram_tab.button)
    next(button for button in histogram_tab.button if button.label == "Calculate RGB histogram").click()
    run_app(app)

    result = app.session_state["pixeltruth_histogram_result"]
    assert result.pixel_count == 12 * 8
    assert result.red[255] == 12 * 8
    assert result.green[255] == 12 * 8
    assert result.blue[255] == 12 * 8
    histogram_tab = app.tabs[5]
    assert any(item.value == "#### Combined RGB intensity distribution" for item in histogram_tab.markdown)

    app.file_uploader[0].set_value(("different.png", make_png("black"), "image/png"))
    run_app(app)
    assert "pixeltruth_histogram_result" not in app.session_state


def test_clearing_upload_removes_histogram_result_and_display():
    app = start_app()
    app.file_uploader[0].set_value(("sample.png", make_png("white"), "image/png"))
    run_app(app)

    histogram_tab = app.tabs[5]
    next(button for button in histogram_tab.button if button.label == "Calculate RGB histogram").click()
    run_app(app)

    assert "pixeltruth_histogram_result" in app.session_state
    assert any(
        item.value == "#### Combined RGB intensity distribution"
        for item in app.tabs[5].markdown
    )
    assert len(app.tabs[5].get("plotly_chart")) == 4

    app.file_uploader[0].clear()
    run_app(app)

    assert "pixeltruth_histogram_result" not in app.session_state
    assert "pixeltruth_histogram_source_hash" not in app.session_state
    assert any(
        "Select a valid image before calculating its RGB histogram" in item.value
        for item in app.tabs[5].info
    )
    assert not any(
        item.value == "#### Combined RGB intensity distribution"
        for item in app.tabs[5].markdown
    )
    assert len(app.tabs[5].get("plotly_chart")) == 0


def test_complete_supported_app_interaction_flow():
    app = start_app()

    gps_image = make_gps_jpeg()
    app.file_uploader[0].set_value(("synthetic-location.jpg", gps_image, "image/jpeg"))
    run_app(app)
    assert any(metric.label == "Format" and metric.value == "JPEG" for metric in app.metric)
    assert len(app.image) == 1
    assert "pixeltruth_gps_result" not in app.session_state

    metadata_headings = [item.value for item in app.tabs[1].markdown]
    assert {"##### EXIF", "##### XMP", "##### IPTC"}.issubset(metadata_headings)

    next(button for button in app.button if button.label == "Reveal GPS information").click()
    run_app(app)
    assert "pixeltruth_gps_result" in app.session_state
    next(button for button in app.button if button.label == "Clear displayed GPS information").click()
    run_app(app)
    assert "pixeltruth_gps_result" not in app.session_state

    comparison_tab = app.tabs[3]
    comparison_tab.file_uploader[0].set_value(("reference.png", make_png("white"), "image/png"))
    comparison_tab.file_uploader[1].set_value(("candidate.png", make_png("black"), "image/png"))
    run_app(app)
    assert any(metric.label == "Sampled pixel similarity indicator" for metric in app.metric)
    assert len(app.image) == 3  # Uploaded inspection preview plus two comparison images.

    app.tabs[4].button[0].click()
    run_app(app)
    assert "pixeltruth_ela_result" in app.session_state
    assert any(metric.label == "Mean RGB difference (0–255)" for metric in app.metric)
