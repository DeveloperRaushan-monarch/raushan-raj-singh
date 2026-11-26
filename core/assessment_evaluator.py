"""Deterministic rule evaluator for PIXELTRUTH Evidence Assessment (PT-EA/1.0.0)."""

from __future__ import annotations

from datetime import datetime

from core.assessment_models import (
    RULE_SET_VERSION,
    Applicability,
    AssessmentFinding,
    CoverageState,
    NotEvaluableReason,
    Relevance,
    RuleEvaluation,
)
from core.assessment_registry import (
    FIELD_VALIDATION_KINDS,
    REGISTERED_FIELD_KEYS,
    RULE_REGISTRY,
)
from core.metadata import FIELD_SPECS, _is_valid, _parse_fraction
from core.models import ImageInspection, ImageProperties, MetadataField, MetadataStatus


ORIENTATION_LABEL_CODES: dict[str, int] = {
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

FIELD_LABELS: dict[str, str] = {key: label for key, label, _, _ in FIELD_SPECS}


def parse_exif_datetime(value: str | None) -> datetime | None:
    """Parse supported EXIF datetime strings without guessing formats."""
    if not value:
        return None
    normalized = value.strip()
    for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(normalized[:19], pattern)
        except ValueError:
            continue
    return None


def parse_positive_int(value: str | None) -> int | None:
    """Parse a positive integer metadata value (including integer rationals)."""
    if not value:
        return None
    parsed = _parse_fraction(value.strip())
    if parsed is None or not parsed.is_integer() or parsed <= 0:
        return None
    return int(parsed)


def parse_orientation_code(value: str | None) -> int | None:
    """Resolve an EXIF orientation value to 1..8, or None if unrecognized."""
    if not value:
        return None
    parsed = _parse_fraction(value.strip())
    if parsed is not None:
        if parsed.is_integer() and 1 <= int(parsed) <= 8:
            return int(parsed)
        return None
    return ORIENTATION_LABEL_CODES.get(value.strip().lower())


def _evaluate_field_validity(
    by_key: dict[str, MetadataField],
) -> tuple[list[RuleEvaluation], list[AssessmentFinding]]:
    rule_id = "metadata-field-value-validity"
    check_id = RULE_REGISTRY[rule_id].check_id
    evaluations: list[RuleEvaluation] = []
    findings: list[AssessmentFinding] = []

    for field_key in REGISTERED_FIELD_KEYS:
        evaluation_id = f"{rule_id}:{field_key}"
        validation_kind = FIELD_VALIDATION_KINDS[field_key]
        field = by_key.get(field_key)
        label = field.label if field else FIELD_LABELS[field_key]

        if field is None or field.status is MetadataStatus.MISSING:
            evaluations.append(
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.NOT_APPLICABLE,
                    applicability_reason=f"{label} field ('{field_key}') is absent from extracted metadata; {label.lower()} consistency cannot be evaluated.",
                    coverage_state=CoverageState.NOT_APPLICABLE,
                    coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                    finding_ids=(),
                )
            )
            continue

        if field.status in {MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE}:
            evaluations.append(
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.UNDETERMINED,
                    applicability_reason=(
                        f"Field '{field_key}' has parser status {field.status.value}."
                    ),
                    coverage_state=CoverageState.NOT_EVALUABLE,
                    coverage_reason=NotEvaluableReason.APPLICABILITY_UNKNOWN.value,
                    finding_ids=(),
                )
            )
            continue

        value_is_valid = (
            field.status is MetadataStatus.PRESENT
            and field.value is not None
            and _is_valid(field.value, validation_kind)
        )
        if value_is_valid:
            evaluations.append(
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.APPLICABLE,
                    applicability_reason=(
                        f"Field '{field_key}' is present with a defined '{validation_kind}' validator."
                    ),
                    coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                    coverage_reason=f"Stored value passed the '{validation_kind}' format/range check.",
                    finding_ids=(),
                )
            )
            continue

        finding_id = f"invalid-metadata-{field_key}"
        evaluations.append(
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason=(
                    f"Field '{field_key}' has a stored value evaluated against '{validation_kind}'."
                ),
                coverage_state=CoverageState.EVALUATED_WITH_FINDING,
                coverage_reason=f"Stored value failed the '{validation_kind}' format/range check.",
                finding_ids=(finding_id,),
            )
        )
        findings.append(
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Metadata validity",
                title=f"{label} has an invalid value",
                relevance=Relevance.REVIEW.value,
                observed_evidence=f"Stored value: {field.value!r}.",
                explanation=field.note or "The value did not pass the field's basic format/range check.",
                possible_interpretations=(
                    "The value may be malformed, outside the defined range, or encoded in an unrecognized form."
                ),
                limitations="A value check does not identify how the value became invalid or show cause or intent.",
                recommended_next_check="Compare the raw tag with another metadata reader or the source device record.",
            )
        )

    return evaluations, findings


def _evaluate_timestamp_comparison(
    by_key: dict[str, MetadataField],
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    rule_id = "exif-original-digitized-time-comparison"
    evaluation_id = rule_id
    check_id = RULE_REGISTRY[rule_id].check_id

    original = by_key.get("datetime_original")
    digitized = by_key.get("datetime_digitized")

    if (
        original is None
        or digitized is None
        or original.status is MetadataStatus.MISSING
        or digitized.status is MetadataStatus.MISSING
    ):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason="Both DateTimeOriginal and DateTimeDigitized must be present for comparison.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    if original.status in {MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE} or digitized.status in {
        MetadataStatus.UNSUPPORTED,
        MetadataStatus.UNAVAILABLE,
    }:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.UNDETERMINED,
                applicability_reason="Parser support or availability for one or both EXIF timestamps is undetermined.",
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.APPLICABILITY_UNKNOWN.value,
                finding_ids=(),
            ),
            [],
        )

    original_time = (
        parse_exif_datetime(original.value)
        if original.status is MetadataStatus.PRESENT
        else None
    )
    digitized_time = (
        parse_exif_datetime(digitized.value)
        if digitized.status is MetadataStatus.PRESENT
        else None
    )
    if original_time is None or digitized_time is None:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason="Both timestamp fields are stored, but at least one is unparseable.",
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value,
                finding_ids=(),
            ),
            [],
        )

    if original_time == digitized_time:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason="Both EXIF DateTimeOriginal and DateTimeDigitized are present and parseable.",
                coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                coverage_reason="DateTimeOriginal and DateTimeDigitized match.",
                finding_ids=(),
            ),
            [],
        )

    finding_id = "timestamp-original-digitized-differ"
    return (
        RuleEvaluation(
            rule_set_version=RULE_SET_VERSION,
            rule_id=rule_id,
            evaluation_id=evaluation_id,
            check_id=check_id,
            applicability=Applicability.APPLICABLE,
            applicability_reason="Both EXIF DateTimeOriginal and DateTimeDigitized are present and parseable.",
            coverage_state=CoverageState.EVALUATED_WITH_FINDING,
            coverage_reason="DateTimeOriginal and DateTimeDigitized differ.",
            finding_ids=(finding_id,),
        ),
        [
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Timestamp consistency",
                title="Capture and digitized timestamps differ",
                relevance=Relevance.INFORMATIONAL.value,
                observed_evidence=(
                    f"DateTimeOriginal is {original.value}; DateTimeDigitized is {digitized.value}."
                ),
                explanation="The two comparable EXIF timestamps do not match.",
                possible_interpretations=(
                    "DateTimeOriginal (capture) and DateTimeDigitized (digitization/storage) can describe "
                    "different events, such as film scans, batch imports, timezone-unaware clocks, or re-exports."
                ),
                limitations="A timestamp difference alone establishes neither an impossible timeline nor alteration.",
                recommended_next_check="Review the source device and any independent capture records if timing matters.",
            )
        ],
    )


def _evaluate_dimension_comparison(
    properties: ImageProperties,
    by_key: dict[str, MetadataField],
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    rule_id = "exif-decoded-dimension-comparison"
    evaluation_id = rule_id
    check_id = RULE_REGISTRY[rule_id].check_id

    width_field = by_key.get("pixel_x_dimension")
    height_field = by_key.get("pixel_y_dimension")
    orientation_field = by_key.get("orientation")

    if (
        width_field is None
        or height_field is None
        or width_field.status is MetadataStatus.MISSING
        or height_field.status is MetadataStatus.MISSING
    ):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason="EXIF pixel_x_dimension and pixel_y_dimension are absent; EXIF dimension comparison cannot be evaluated.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    if (
        width_field.status in {MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE}
        or height_field.status in {MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE}
        or (
            orientation_field is not None
            and orientation_field.status in {MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE}
        )
    ):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.UNDETERMINED,
                applicability_reason="Parser support or availability for EXIF dimensions or orientation is undetermined.",
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.APPLICABILITY_UNKNOWN.value,
                finding_ids=(),
            ),
            [],
        )

    exif_width = (
        parse_positive_int(width_field.value)
        if width_field.status is MetadataStatus.PRESENT
        else None
    )
    exif_height = (
        parse_positive_int(height_field.value)
        if height_field.status is MetadataStatus.PRESENT
        else None
    )
    if exif_width is None or exif_height is None or properties.width <= 0 or properties.height <= 0:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason="EXIF pixel dimensions are present, but one or both values are unparseable.",
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value,
                finding_ids=(),
            ),
            [],
        )

    metadata_size = (exif_width, exif_height)
    actual_size = (properties.width, properties.height)
    swapped_size = (properties.height, properties.width)

    if orientation_field is None or orientation_field.status is MetadataStatus.MISSING:
        if metadata_size == actual_size:
            return (
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.APPLICABLE,
                    applicability_reason="EXIF dimensions are present and match decoded raster dimensions directly.",
                    coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                    coverage_reason="EXIF dimensions match decoded raster dimensions directly.",
                    finding_ids=(),
                ),
                [],
            )
        if metadata_size == swapped_size:
            return (
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.APPLICABLE,
                    applicability_reason="EXIF dimensions match swapped raster dimensions, but orientation is missing.",
                    coverage_state=CoverageState.NOT_EVALUABLE,
                    coverage_reason=NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value,
                    finding_ids=(),
                ),
                [],
            )
    else:
        orientation_code = (
            parse_orientation_code(orientation_field.value)
            if orientation_field.status is MetadataStatus.PRESENT
            else None
        )
        if orientation_code is None:
            if metadata_size == actual_size:
                return (
                    RuleEvaluation(
                        rule_set_version=RULE_SET_VERSION,
                        rule_id=rule_id,
                        evaluation_id=evaluation_id,
                        check_id=check_id,
                        applicability=Applicability.APPLICABLE,
                        applicability_reason="EXIF dimensions match decoded raster dimensions directly.",
                        coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                        coverage_reason="EXIF dimensions match decoded raster dimensions directly.",
                        finding_ids=(),
                    ),
                    [],
                )
            return (
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.APPLICABLE,
                    applicability_reason="EXIF orientation is invalid or unrecognized for non-direct dimension comparison.",
                    coverage_state=CoverageState.NOT_EVALUABLE,
                    coverage_reason=NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value,
                    finding_ids=(),
                ),
                [],
            )

        allowed_sizes = {actual_size}
        if orientation_code in {5, 6, 7, 8}:
            allowed_sizes.add(swapped_size)

        if metadata_size in allowed_sizes:
            return (
                RuleEvaluation(
                    rule_set_version=RULE_SET_VERSION,
                    rule_id=rule_id,
                    evaluation_id=evaluation_id,
                    check_id=check_id,
                    applicability=Applicability.APPLICABLE,
                    applicability_reason=(
                        f"EXIF dimensions and orientation ({orientation_code}) are present and valid."
                    ),
                    coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                    coverage_reason="EXIF dimensions are consistent with decoded raster dimensions.",
                    finding_ids=(),
                ),
                [],
            )

    finding_id = "exif-pixel-dimensions-differ"
    return (
        RuleEvaluation(
            rule_set_version=RULE_SET_VERSION,
            rule_id=rule_id,
            evaluation_id=evaluation_id,
            check_id=check_id,
            applicability=Applicability.APPLICABLE,
            applicability_reason="EXIF dimensions and decoded raster dimensions are comparable.",
            coverage_state=CoverageState.EVALUATED_WITH_FINDING,
            coverage_reason="EXIF pixel dimensions differ from decoded raster dimensions.",
            finding_ids=(finding_id,),
        ),
        [
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=evaluation_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Dimension consistency",
                title="EXIF pixel dimensions differ from decoded dimensions",
                relevance=Relevance.REVIEW.value,
                observed_evidence=(
                    f"EXIF reports {exif_width} × {exif_height} px; "
                    f"decoded image data is {properties.width} × {properties.height} px."
                ),
                explanation="Stored EXIF dimensions do not match the dimensions decoded from the image data.",
                possible_interpretations=(
                    "The metadata may be stale, the image may have been resized, or a format-specific "
                    "orientation convention may affect the reported dimensions."
                ),
                limitations="This comparison establishes disagreement only and does not identify when or why the values diverged.",
                recommended_next_check="Inspect the image orientation and compare against the original file or device record.",
            )
        ],
    )


def _safe_run_rule(
    rule_id: str,
    fn,
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    """Run a singleton rule safely; execution errors become APPLICABLE / NOT_EVALUABLE."""
    try:
        return fn()
    except Exception as exc:
        check_id = RULE_REGISTRY[rule_id].check_id
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason=f"Rule '{rule_id}' was applicable but encountered an execution error.",
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.FAILED.value,
                finding_ids=(),
            ),
            [],
        )


def _evaluate_image_properties(
    properties: ImageProperties,
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    rule_id = "image-properties-consistency"
    check_id = RULE_REGISTRY[rule_id].check_id
    issues: list[str] = []
    if properties.width <= 0 or properties.height <= 0:
        issues.append("Decoded width/height must be positive.")
    if properties.frame_count < 1:
        issues.append("Frame count must be at least 1.")
    if not properties.color_mode:
        issues.append("Colour mode is missing.")
    if properties.bit_depth_per_channel is not None and properties.bit_depth_per_channel <= 0:
        issues.append("Bit depth per channel must be positive.")

    if not issues:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason="Decoded ImageProperties are available from the image decoder.",
                coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                coverage_reason=(
                    f"Decoded dimensions ({properties.width} × {properties.height} px), colour mode "
                    f"({properties.color_mode}), and frame count ({properties.frame_count}) are internally consistent."
                ),
                finding_ids=(),
            ),
            [],
        )

    finding_id = "image-properties-inconsistent"
    return (
        RuleEvaluation(
            rule_set_version=RULE_SET_VERSION,
            rule_id=rule_id,
            evaluation_id=rule_id,
            check_id=check_id,
            applicability=Applicability.APPLICABLE,
            applicability_reason="Decoded ImageProperties are available from the image decoder.",
            coverage_state=CoverageState.EVALUATED_WITH_FINDING,
            coverage_reason="One or more decoded image properties are inconsistent.",
            finding_ids=(finding_id,),
        ),
        [
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Image structure",
                title="Decoded image properties are inconsistent",
                relevance=Relevance.REVIEW.value,
                observed_evidence=" ".join(issues),
                explanation="Image decoder properties did not satisfy basic structural consistency checks.",
                possible_interpretations="The container header or decoder state may be malformed.",
                limitations="Structural inconsistency does not identify how or why the file was modified.",
                recommended_next_check="Re-inspect the file container and headers.",
            )
        ],
    )


def _evaluate_container_structure(
    inspection: ImageInspection,
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    rule_id = "container-structure-integrity"
    check_id = RULE_REGISTRY[rule_id].check_id
    inv = getattr(inspection, "inventory", None)
    if inv is None or not getattr(inv, "coverage", None):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason="MetadataInventory container stage was not supplied for this inspection.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    stage = next((s for s in inv.coverage.stages if s.stage_id == "container"), None)
    if stage is None:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason="Container extraction stage was not present.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    state_val = stage.completion_state.value if hasattr(stage.completion_state, "value") else str(stage.completion_state)
    if state_val == "COMPLETED":
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason="Container structure and format headers are available.",
                coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                coverage_reason=f"Container structure ({inspection.properties.image_format}) parsed cleanly with {stage.records_extracted} record(s).",
                finding_ids=(),
            ),
            [],
        )

    finding_id = "container-structure-warning"
    warn_text = "; ".join(w.message for w in stage.warnings) or f"Container stage reported {state_val}."
    return (
        RuleEvaluation(
            rule_set_version=RULE_SET_VERSION,
            rule_id=rule_id,
            evaluation_id=rule_id,
            check_id=check_id,
            applicability=Applicability.APPLICABLE,
            applicability_reason="Container structure extraction encountered warnings or errors.",
            coverage_state=CoverageState.EVALUATED_WITH_FINDING,
            coverage_reason=f"Container stage completed with status {state_val}.",
            finding_ids=(finding_id,),
        ),
        [
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Container structure",
                title="Container structure parser reported warnings",
                relevance=Relevance.REVIEW.value,
                observed_evidence=warn_text,
                explanation="Container header/chunk parsing did not complete cleanly.",
                possible_interpretations="The file may have non-standard or truncated container chunks.",
                limitations="Container parser warnings do not establish intentional manipulation.",
                recommended_next_check="Inspect container chunk records in Metadata Explorer.",
            )
        ],
    )


def _evaluate_optional_stage(
    inspection: ImageInspection,
    *,
    rule_id: str,
    stage_id: str,
    label: str,
    finding_id: str,
    fail_on_partial: bool = False,
) -> tuple[RuleEvaluation, list[AssessmentFinding]]:
    check_id = RULE_REGISTRY[rule_id].check_id
    inv = getattr(inspection, "inventory", None)
    if inv is None or not getattr(inv, "coverage", None):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason=f"MetadataInventory was not supplied; {label} stage cannot be evaluated.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    stage = next((s for s in inv.coverage.stages if s.stage_id == stage_id), None)
    if stage is None:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason=f"{label} stage is absent from extraction coverage.",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    state_val = stage.completion_state.value if hasattr(stage.completion_state, "value") else str(stage.completion_state)
    if state_val in {"EMPTY", "UNSUPPORTED", "SKIPPED_RESOURCE_LIMIT"}:
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.NOT_APPLICABLE,
                applicability_reason=f"No {label} block was present or supported in this image ({state_val}).",
                coverage_state=CoverageState.NOT_APPLICABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
            [],
        )

    if state_val == "COMPLETED" or (state_val == "PARTIAL" and not fail_on_partial):
        return (
            RuleEvaluation(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                applicability=Applicability.APPLICABLE,
                applicability_reason=f"{label} metadata is present in this image.",
                coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                coverage_reason=f"{label} structure parsed cleanly ({stage.records_extracted} record(s)).",
                finding_ids=(),
            ),
            [],
        )

    warn_text = "; ".join(w.message for w in stage.warnings) or f"{label} stage reported {state_val}."
    return (
        RuleEvaluation(
            rule_set_version=RULE_SET_VERSION,
            rule_id=rule_id,
            evaluation_id=rule_id,
            check_id=check_id,
            applicability=Applicability.APPLICABLE,
            applicability_reason=f"{label} metadata is present but failed structural validation.",
            coverage_state=CoverageState.EVALUATED_WITH_FINDING,
            coverage_reason=f"{label} stage reported {state_val}.",
            finding_ids=(finding_id,),
        ),
        [
            AssessmentFinding(
                rule_set_version=RULE_SET_VERSION,
                rule_id=rule_id,
                evaluation_id=rule_id,
                check_id=check_id,
                finding_id=finding_id,
                category="Metadata integrity",
                title=f"Malformed {label} metadata",
                relevance=Relevance.REVIEW.value,
                observed_evidence=warn_text,
                explanation=f"The embedded {label} structure could not be parsed cleanly.",
                possible_interpretations=f"The {label} block may be truncated, corrupted, or non-conformant.",
                limitations=f"Malformed {label} data does not establish cause or intent.",
                recommended_next_check=f"Review {label} extraction warnings in Metadata Explorer.",
            )
        ],
    )


def evaluate_inspection(
    inspection: ImageInspection,
) -> tuple[tuple[RuleEvaluation, ...], tuple[AssessmentFinding, ...]]:
    """Run all registered PT-EA rules deterministically against an inspection."""
    by_key = {field.key: field for field in inspection.metadata}
    evaluations: list[RuleEvaluation] = []
    findings: list[AssessmentFinding] = []

    fv_evals, fv_findings = _evaluate_field_validity(by_key)
    evaluations.extend(fv_evals)
    findings.extend(fv_findings)

    ts_eval, ts_findings = _evaluate_timestamp_comparison(by_key)
    evaluations.append(ts_eval)
    findings.extend(ts_findings)

    dim_eval, dim_findings = _evaluate_dimension_comparison(inspection.properties, by_key)
    evaluations.append(dim_eval)
    findings.extend(dim_findings)

    for rid, runner in (
        ("image-properties-consistency", lambda: _evaluate_image_properties(inspection.properties)),
        ("container-structure-integrity", lambda: _evaluate_container_structure(inspection)),
        (
            "embedded-xmp-integrity",
            lambda: _evaluate_optional_stage(
                inspection,
                rule_id="embedded-xmp-integrity",
                stage_id="xmp",
                label="XMP packet",
                finding_id="xmp-packet-malformed",
                fail_on_partial=False,
            ),
        ),
        (
            "embedded-icc-integrity",
            lambda: _evaluate_optional_stage(
                inspection,
                rule_id="embedded-icc-integrity",
                stage_id="icc",
                label="ICC profile",
                finding_id="icc-profile-malformed",
                fail_on_partial=False,
            ),
        ),
    ):
        ev, fds = _safe_run_rule(rid, runner)
        evaluations.append(ev)
        findings.extend(fds)

    sorted_evals = tuple(
        sorted(evaluations, key=lambda item: (item.rule_id, item.evaluation_id))
    )
    sorted_findings = tuple(
        sorted(
            findings,
            key=lambda item: (item.rule_id, item.evaluation_id, item.finding_id),
        )
    )
    return sorted_evals, sorted_findings
