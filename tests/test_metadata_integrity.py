from core.metadata_integrity import inspect_metadata_integrity
from core.models import ImageProperties, MetadataField, MetadataStatus


def properties():
    return ImageProperties(
        filename="sample.jpg", file_size_bytes=100, image_format="JPEG", mime_type="image/jpeg",
        width=100, height=80, aspect_ratio=1.25, megapixels=0.008, color_mode="RGB",
        bit_depth_per_channel=8, frame_count=1, has_transparency=False, extension_mismatch=False,
    )


def field(key, label, value, status):
    return MetadataField(key, label, value, status)


def test_missing_metadata_is_informational_not_a_manipulation_claim():
    findings = inspect_metadata_integrity(
        properties(),
        (
            field("make", "Camera make", None, MetadataStatus.MISSING),
            field("xmp", "XMP metadata", None, MetadataStatus.UNSUPPORTED),
        ),
    )
    missing = next(item for item in findings if item.finding_id == "common-metadata-fields-missing")
    assert missing.relevance == "Informational"
    assert "does not show" in missing.confidence_limitations
    assert all(item.relevance != "Review" for item in findings)


def test_invalid_values_produce_explainable_review_finding():
    findings = inspect_metadata_integrity(
        properties(),
        (field("orientation", "Orientation", "9", MetadataStatus.INVALID),),
    )
    invalid = next(item for item in findings if item.finding_id == "invalid-metadata-orientation")
    assert invalid.relevance == "Review"
    assert invalid.observed_evidence == "Stored value: '9'."
    assert invalid.recommended_next_check


def test_exif_dimensions_match_when_rotation_swaps_axes():
    fields = (
        field("pixel_x_dimension", "EXIF pixel width", "80", MetadataStatus.PRESENT),
        field("pixel_y_dimension", "EXIF pixel height", "100", MetadataStatus.PRESENT),
        field("orientation", "Orientation", "Rotated 90 CW", MetadataStatus.PRESENT),
    )
    findings = inspect_metadata_integrity(properties(), fields)
    assert not any(item.finding_id == "exif-pixel-dimensions-differ" for item in findings)


def test_comparable_capture_timestamps_are_checked():
    fields = (
        field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
        field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
    )
    findings = inspect_metadata_integrity(properties(), fields)
    timestamp = next(item for item in findings if item.finding_id == "timestamp-original-digitized-differ")
    assert timestamp.relevance == "Informational"
    assert "does not establish editing" in timestamp.confidence_limitations


def test_exif_dimension_mismatch_is_reported_with_orientation_context():
    fields = (
        field("pixel_x_dimension", "EXIF pixel width", "640", MetadataStatus.PRESENT),
        field("pixel_y_dimension", "EXIF pixel height", "480", MetadataStatus.PRESENT),
        field("orientation", "Orientation", "Horizontal (normal)", MetadataStatus.PRESENT),
    )
    findings = inspect_metadata_integrity(properties(), fields)
    mismatch = next(item for item in findings if item.finding_id == "exif-pixel-dimensions-differ")
    assert mismatch.relevance == "Review"
    assert "decoded image data is 100 × 80" in mismatch.observed_evidence
