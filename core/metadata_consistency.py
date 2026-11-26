"""Conservative cross-field checks for metadata values and decoded properties."""

from datetime import datetime

from core.models import Finding, ImageProperties, MetadataField, MetadataStatus


ORIENTATION_LABEL_CODES = {
    "horizontal (normal)": 1,
    "mirror horizontal": 2,
    "mirrored horizontal": 2,
    "rotate 180": 3,
    "rotated 180": 3,
    "mirror vertical": 4,
    "mirrored vertical": 4,
    "mirror horizontal and rotate 270 cw": 5,
    "mirrored horizontal then rotated 90 ccw": 5,
    "rotate 90 cw": 6,
    "rotated 90 cw": 6,
    "mirror horizontal and rotate 90 cw": 7,
    "mirrored horizontal then rotated 90 cw": 7,
    "rotate 270 cw": 8,
    "rotated 90 ccw": 8,
}


def _field_map(fields: tuple[MetadataField, ...]) -> dict[str, MetadataField]:
    return {field.key: field for field in fields}


def _parse_datetime(value: str) -> datetime | None:
    for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:19], pattern)
        except ValueError:
            continue
    return None


def _orientation_code(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        number = int(value)
        return number if 1 <= number <= 8 else None
    except ValueError:
        return ORIENTATION_LABEL_CODES.get(value.strip().lower())


def inspect_metadata_consistency(
    properties: ImageProperties, fields: tuple[MetadataField, ...]
) -> tuple[Finding, ...]:
    """Return explainable observations where comparable metadata disagrees."""
    by_key = _field_map(fields)
    findings: list[Finding] = []

    original = by_key.get("datetime_original")
    digitized = by_key.get("datetime_digitized")
    if (
        original
        and digitized
        and original.status is MetadataStatus.PRESENT
        and digitized.status is MetadataStatus.PRESENT
        and original.value
        and digitized.value
    ):
        original_time = _parse_datetime(original.value)
        digitized_time = _parse_datetime(digitized.value)
        if original_time and digitized_time and original_time != digitized_time:
            findings.append(
                Finding(
                    finding_id="timestamp-original-digitized-differ",
                    category="Timestamp consistency",
                    title="Capture and digitized timestamps differ",
                    relevance="Informational",
                    observed_evidence=(
                        f"DateTimeOriginal is {original.value}; DateTimeDigitized is {digitized.value}."
                    ),
                    explanation="The two comparable EXIF timestamps do not match.",
                    possible_interpretations=(
                        "The values may reflect capture and later digitization, different device clocks, "
                        "or a metadata change."
                    ),
                    confidence_limitations="A timestamp difference alone does not establish editing or tampering.",
                    recommended_next_check="Review the source device and any independent capture records.",
                )
            )

    width_field = by_key.get("pixel_x_dimension")
    height_field = by_key.get("pixel_y_dimension")
    if (
        width_field
        and height_field
        and width_field.status is MetadataStatus.PRESENT
        and height_field.status is MetadataStatus.PRESENT
        and width_field.value
        and height_field.value
    ):
        try:
            metadata_size = (int(width_field.value), int(height_field.value))
        except ValueError:
            metadata_size = None
        actual_size = (properties.width, properties.height)
        swapped_size = (properties.height, properties.width)
        orientation_field = by_key.get("orientation")
        orientation = (
            _orientation_code(orientation_field.value)
            if orientation_field and orientation_field.status is MetadataStatus.PRESENT
            else None
        )
        should_emit = False
        if metadata_size is not None:
            if orientation_field is None or orientation_field.status is MetadataStatus.MISSING:
                # Direct equality passes; swapped-only is ambiguous (not evaluable); other mismatch emits Review.
                should_emit = metadata_size not in {actual_size, swapped_size}
            elif orientation is None:
                # Invalid/unrecognized orientation: direct equality passes; any non-direct match is not evaluable.
                should_emit = False
            else:
                allowed_sizes = {actual_size}
                if orientation in {5, 6, 7, 8}:
                    allowed_sizes.add(swapped_size)
                should_emit = metadata_size not in allowed_sizes
        if should_emit and metadata_size is not None:
            findings.append(
                Finding(
                    finding_id="exif-pixel-dimensions-differ",
                    category="Dimension consistency",
                    title="EXIF pixel dimensions differ from decoded dimensions",
                    relevance="Review",
                    observed_evidence=(
                        f"EXIF reports {metadata_size[0]} × {metadata_size[1]} px; "
                        f"decoded image data is {properties.width} × {properties.height} px."
                    ),
                    explanation="Stored EXIF dimensions do not match the dimensions decoded from the image data.",
                    possible_interpretations=(
                        "The metadata may be stale, the image may have been resized, or a format-specific "
                        "orientation convention may affect the reported dimensions."
                    ),
                    confidence_limitations="This comparison does not identify when or why the values diverged.",
                    recommended_next_check="Inspect the image orientation and compare against the original file or device record.",
                )
            )
    return tuple(findings)
