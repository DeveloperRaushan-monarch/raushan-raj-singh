"""Complete test matrix for Phase 3.3 Evidence Assessment (PT-EA/1.0.0)."""

from __future__ import annotations

from io import BytesIO
import json
import re

import pytest
from PIL import Image

from core.analysis import inspect_image
from core.assessment_engine import BASE_WORDING, BOUNDARY_STATEMENT, assess_inspection, assess_records
from core.assessment_evaluator import evaluate_inspection
from core.assessment_models import (
    RULE_SET_VERSION,
    Applicability,
    AssessmentFinding,
    AssessmentOutcome,
    CoverageState,
    NotEvaluableReason,
    Relevance,
    RuleEvaluation,
)
from core.models import Finding, ImageInspection, ImageProperties, MetadataField, MetadataStatus
from utils.validators import ImageValidationError


def _make_properties(
    *,
    image_format: str = "JPEG",
    width: int = 100,
    height: int = 80,
    filename: str = "sample.jpg",
) -> ImageProperties:
    return ImageProperties(
        filename=filename,
        file_size_bytes=2048,
        image_format=image_format,
        mime_type=f"image/{image_format.lower()}",
        width=width,
        height=height,
        aspect_ratio=round(width / height, 4) if height else 0.0,
        megapixels=round((width * height) / 1_000_000, 6),
        color_mode="RGB",
        bit_depth_per_channel=8,
        frame_count=1,
        has_transparency=False,
        extension_mismatch=False,
    )


def _make_inspection(
    fields: tuple[MetadataField, ...] = (),
    *,
    image_format: str = "JPEG",
    width: int = 100,
    height: int = 80,
) -> ImageInspection:
    return ImageInspection(
        properties=_make_properties(image_format=image_format, width=width, height=height),
        metadata=fields,
        sha256="a" * 64,
    )


def _field(key: str, label: str, value: str | None, status: MetadataStatus) -> MetadataField:
    return MetadataField(key=key, label=label, value=value, status=status, source="EXIF")


def _eval_by_id(result, evaluation_id: str) -> RuleEvaluation:
    return next(ev for ev in result.evaluations if ev.evaluation_id == evaluation_id)


def _valid_finding(
    *,
    rule_id: str = "metadata-field-value-validity",
    evaluation_id: str = "metadata-field-value-validity:orientation",
    check_id: str = "metadata-integrity-check",
    finding_id: str = "invalid-metadata-orientation",
    relevance: str = "Review",
    rule_set_version: str = RULE_SET_VERSION,
) -> AssessmentFinding:
    return AssessmentFinding(
        rule_set_version=rule_set_version,
        rule_id=rule_id,
        evaluation_id=evaluation_id,
        check_id=check_id,
        finding_id=finding_id,
        category="Metadata validity",
        title="Orientation has an invalid value",
        relevance=relevance,
        observed_evidence="Stored value: '9'.",
        explanation="The stored value does not match the expected format or range.",
        possible_interpretations="The value may be malformed or outside the defined range.",
        limitations="A value check does not identify how the value became invalid.",
        recommended_next_check="Compare the raw tag with another metadata reader.",
    )


def _valid_eval(
    *,
    rule_id: str = "metadata-field-value-validity",
    evaluation_id: str = "metadata-field-value-validity:orientation",
    check_id: str = "metadata-integrity-check",
    applicability: Applicability | str = Applicability.APPLICABLE,
    coverage_state: CoverageState | str = CoverageState.EVALUATED_WITH_FINDING,
    coverage_reason: str = "Stored value failed the 'orientation' format/range check.",
    finding_ids: tuple[str, ...] = ("invalid-metadata-orientation",),
    rule_set_version: str = RULE_SET_VERSION,
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_set_version=rule_set_version,
        rule_id=rule_id,
        evaluation_id=evaluation_id,
        check_id=check_id,
        applicability=applicability,
        applicability_reason="Field is present with a defined validator.",
        coverage_state=coverage_state,
        coverage_reason=coverage_reason,
        finding_ids=finding_ids,
    )


# ---------------------------------------------------------------------------
# 8.1 Core framework, outcome, and integrity tests
# ---------------------------------------------------------------------------


def test_t_invalid_input_rejected_before_assessment():
    with pytest.raises(ImageValidationError):
        inspect_image(b"not-a-valid-image", "broken.jpg")


def test_t_lc_01_valid_make_and_matching_dimensions():
    inspection = _make_inspection(
        (
            _field("make", "Camera make", "Canon", MetadataStatus.PRESENT),
            _field("pixel_x_dimension", "EXIF pixel width", "100", MetadataStatus.PRESENT),
            _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
            _field("orientation", "Orientation", "1", MetadataStatus.PRESENT),
        )
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.LOW_CONCERN
    assert _eval_by_id(result, "metadata-field-value-validity:make").coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert _eval_by_id(result, "exif-decoded-dimension-comparison").coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value


def test_t_lc_02_valid_make_with_missing_dimensions_does_not_block():
    inspection = _make_inspection(
        (
            _field("make", "Camera make", "Canon", MetadataStatus.PRESENT),
            _field("pixel_x_dimension", "EXIF pixel width", None, MetadataStatus.MISSING),
            _field("pixel_y_dimension", "EXIF pixel height", None, MetadataStatus.MISSING),
        )
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.LOW_CONCERN
    dim_eval = _eval_by_id(result, "exif-decoded-dimension-comparison")
    assert dim_eval.applicability == Applicability.NOT_APPLICABLE.value
    assert dim_eval.coverage_state == CoverageState.NOT_EVALUABLE.value


def test_t_lc_03_timestamp_difference_is_informational_not_review():
    inspection = _make_inspection(
        (
            _field("make", "Camera make", "Canon", MetadataStatus.PRESENT),
            _field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
            _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
        )
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.LOW_CONCERN
    ts_finding = next(f for f in result.findings if f.finding_id == "timestamp-original-digitized-differ")
    assert ts_finding.relevance == Relevance.INFORMATIONAL.value


def test_t_nr_01_invalid_orientation_triggers_needs_review():
    inspection = _make_inspection(
        (_field("orientation", "Orientation", "9", MetadataStatus.INVALID),)
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.NEEDS_REVIEW
    finding = next(f for f in result.findings if f.finding_id == "invalid-metadata-orientation")
    assert finding.relevance == Relevance.REVIEW.value


def test_t_nr_02_dimension_mismatch_triggers_needs_review():
    inspection = _make_inspection(
        (
            _field("pixel_x_dimension", "EXIF pixel width", "640", MetadataStatus.PRESENT),
            _field("pixel_y_dimension", "EXIF pixel height", "480", MetadataStatus.PRESENT),
            _field("orientation", "Orientation", "1", MetadataStatus.PRESENT),
        ),
        width=100,
        height=80,
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.NEEDS_REVIEW
    finding = next(f for f in result.findings if f.finding_id == "exif-pixel-dimensions-differ")
    assert finding.relevance == Relevance.REVIEW.value


def test_t_nr_03_review_finding_not_cancelled_by_passing_or_informational():
    inspection = _make_inspection(
        (
            _field("make", "Camera make", "Canon", MetadataStatus.PRESENT),
            _field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
            _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
            _field("orientation", "Orientation", "9", MetadataStatus.INVALID),
        )
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.NEEDS_REVIEW
    assert any(f.finding_id == "timestamp-original-digitized-differ" for f in result.findings)
    assert any(f.finding_id == "invalid-metadata-orientation" for f in result.findings)


def test_t_nr_04_review_finding_alongside_unavailable_check_discloses_both():
    inspection = _make_inspection(
        (
            _field("orientation", "Orientation", "9", MetadataStatus.INVALID),
            _field("make", "Camera make", None, MetadataStatus.UNAVAILABLE),
        )
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.NEEDS_REVIEW
    assert any(f.finding_id == "invalid-metadata-orientation" for f in result.findings)
    assert any("metadata-field-value-validity:make" in note for note in result.limitations)


def test_t_ie_01_bmp_all_unsupported():
    buffer = BytesIO()
    Image.new("RGB", (32, 32), color=(100, 120, 140)).save(buffer, format="BMP")
    inspection = inspect_image(buffer.getvalue(), "sample.bmp")
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ie_02_jpeg_all_missing():
    buffer = BytesIO()
    Image.new("RGB", (32, 32), color=(100, 120, 140)).save(buffer, format="JPEG")
    inspection = inspect_image(buffer.getvalue(), "sample.jpg")
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ie_03_only_ela_and_histogram_no_metadata():
    inspection = _make_inspection(())
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ie_04_hash_or_software_tag_alone_is_insufficient_and_never_review():
    inspection = _make_inspection(
        (_field("software", "Editing software", "Adobe Photoshop", MetadataStatus.PRESENT),)
    )
    result = assess_inspection(inspection)
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert not result.findings


def test_t_ie_05_valid_metadata_blocked_by_critical_dimension_gap():
    inspection = _make_inspection(
        (
            _field("make", "Camera make", "Canon", MetadataStatus.PRESENT),
            _field("pixel_x_dimension", "EXIF pixel width", "abc", MetadataStatus.INVALID),
            _field("pixel_y_dimension", "EXIF pixel height", "def", MetadataStatus.INVALID),
        )
    )
    # Remove the INVALID findings from field-validity or test dimension rule directly:
    # Even if make is valid and dimension rule is NOT_EVALUABLE (malformed dims),
    # here pixel_x_dimension is INVALID so field-validity emits Review; test Rule C/D directly
    # with valid make + NOT_EVALUABLE critical dimension rule:
    valid_make_eval = _valid_eval(
        evaluation_id="metadata-field-value-validity:make",
        coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
        coverage_reason="Stored value passed the 'text' format/range check.",
        finding_ids=(),
    )
    not_eval_dim = _valid_eval(
        rule_id="exif-decoded-dimension-comparison",
        evaluation_id="exif-decoded-dimension-comparison",
        check_id="metadata-consistency-check",
        applicability=Applicability.APPLICABLE,
        coverage_state=CoverageState.NOT_EVALUABLE,
        coverage_reason=NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value,
        finding_ids=(),
    )
    result = assess_records((valid_make_eval, not_eval_dim), ())
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE

    undetermined_dim = _valid_eval(
        rule_id="exif-decoded-dimension-comparison",
        evaluation_id="exif-decoded-dimension-comparison",
        check_id="metadata-consistency-check",
        applicability=Applicability.UNDETERMINED,
        coverage_state=CoverageState.NOT_EVALUABLE,
        coverage_reason=NotEvaluableReason.APPLICABILITY_UNKNOWN.value,
        finding_ids=(),
    )
    result_undetermined = assess_records((valid_make_eval, undetermined_dim), ())
    assert result_undetermined.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert inspection.sha256


# ---------------------------------------------------------------------------
# 8.2 Rule-specific tests
# ---------------------------------------------------------------------------


def test_t_fv_01_orientation_valid():
    evals, findings = evaluate_inspection(
        _make_inspection((_field("orientation", "Orientation", "6", MetadataStatus.PRESENT),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:orientation")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_fv_02_orientation_invalid():
    evals, findings = evaluate_inspection(
        _make_inspection((_field("orientation", "Orientation", "9", MetadataStatus.INVALID),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:orientation")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert ev.finding_ids == ("invalid-metadata-orientation",)
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_fv_03_orientation_missing():
    evals, _ = evaluate_inspection(
        _make_inspection((_field("orientation", "Orientation", None, MetadataStatus.MISSING),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:orientation")
    assert ev.applicability == Applicability.NOT_APPLICABLE.value
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value


@pytest.mark.parametrize("status", [MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE])
def test_t_fv_04_orientation_unsupported_or_unavailable(status):
    evals, findings = evaluate_inspection(
        _make_inspection((_field("orientation", "Orientation", None, status),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:orientation")
    assert ev.applicability == Applicability.UNDETERMINED.value
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.APPLICABILITY_UNKNOWN.value
    assert not findings


def test_t_fv_05_iso_valid():
    evals, findings = evaluate_inspection(
        _make_inspection((_field("iso", "ISO", "400", MetadataStatus.PRESENT),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:iso")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_fv_06_iso_invalid():
    evals, findings = evaluate_inspection(
        _make_inspection((_field("iso", "ISO", "-1", MetadataStatus.INVALID),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:iso")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_fv_07_exposure_time_zero_invalid():
    evals, findings = evaluate_inspection(
        _make_inspection((_field("exposure_time", "Exposure time", "0", MetadataStatus.INVALID),))
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:exposure_time")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_fv_08_datetime_original_valid():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (_field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),)
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:datetime_original")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_fv_09_datetime_original_invalid():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (_field("datetime_original", "Capture date and time", "not a date", MetadataStatus.INVALID),)
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "metadata-field-value-validity:datetime_original")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_ts_01_timestamps_equal():
    inspection = _make_inspection(
        (
            _field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
            _field("datetime_digitized", "Date digitized", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
        )
    )
    evals, findings = evaluate_inspection(inspection)
    ev = next(item for item in evals if item.evaluation_id == "exif-original-digitized-time-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings
    # Timestamp rule alone never supplies substantive coverage:
    result = assess_records((ev,), ())
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ts_02_timestamps_different_informational():
    inspection = _make_inspection(
        (
            _field("datetime_original", "Capture date and time", "2024:01:02 10:00:00", MetadataStatus.PRESENT),
            _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
        )
    )
    result = assess_inspection(inspection)
    ev = _eval_by_id(result, "exif-original-digitized-time-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    finding = next(f for f in result.findings if f.finding_id == "timestamp-original-digitized-differ")
    assert finding.relevance == Relevance.INFORMATIONAL.value
    assert result.outcome is AssessmentOutcome.LOW_CONCERN


def test_t_ts_03_one_timestamp_missing():
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("datetime_original", "Capture date and time", None, MetadataStatus.MISSING),
                _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-original-digitized-time-comparison")
    assert ev.applicability == Applicability.NOT_APPLICABLE.value


def test_t_ts_04_timestamp_unparseable():
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("datetime_original", "Capture date and time", "bad-date", MetadataStatus.INVALID),
                _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-original-digitized-time-comparison")
    assert ev.applicability == Applicability.APPLICABLE.value
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value


@pytest.mark.parametrize("status", [MetadataStatus.UNSUPPORTED, MetadataStatus.UNAVAILABLE])
def test_t_ts_05_timestamp_unsupported_or_unavailable(status):
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("datetime_original", "Capture date and time", None, status),
                _field("datetime_digitized", "Date digitized", "2024:01:02 10:05:00", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-original-digitized-time-comparison")
    assert ev.applicability == Applicability.UNDETERMINED.value
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.APPLICABILITY_UNKNOWN.value


def test_t_dim_01_direct_match_orientation_1():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "100", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "1", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_dim_02_mismatch_orientation_1():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "640", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "480", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "1", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_dim_03_swapped_match_orientation_6():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "80", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "100", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "6", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_dim_04_direct_match_orientation_6():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "100", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "6", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_dim_05_swapped_mismatch_orientation_1():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "80", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "100", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "1", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITH_FINDING.value
    assert findings[0].relevance == Relevance.REVIEW.value


def test_t_dim_06_swapped_only_missing_orientation_not_evaluable():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "80", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "100", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", None, MetadataStatus.MISSING),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value
    assert not findings


def test_t_dim_07_direct_match_missing_orientation():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "100", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", None, MetadataStatus.MISSING),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


def test_t_dim_08_invalid_orientation_non_direct_not_evaluable():
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "80", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "100", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "9", MetadataStatus.INVALID),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value


def test_t_dim_09_missing_dimension_not_applicable():
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", None, MetadataStatus.MISSING),
                _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.applicability == Applicability.NOT_APPLICABLE.value


def test_t_dim_10_unparseable_dimensions_not_evaluable():
    evals, _ = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "abc", MetadataStatus.INVALID),
                _field("pixel_y_dimension", "EXIF pixel height", "def", MetadataStatus.INVALID),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.NOT_EVALUABLE.value
    assert ev.coverage_reason == NotEvaluableReason.MISSING_REQUIRED_EVIDENCE.value


def test_t_dim_11_orientation_3_direct_match():
    evals, findings = evaluate_inspection(
        _make_inspection(
            (
                _field("pixel_x_dimension", "EXIF pixel width", "100", MetadataStatus.PRESENT),
                _field("pixel_y_dimension", "EXIF pixel height", "80", MetadataStatus.PRESENT),
                _field("orientation", "Orientation", "3", MetadataStatus.PRESENT),
            )
        )
    )
    ev = next(item for item in evals if item.evaluation_id == "exif-decoded-dimension-comparison")
    assert ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
    assert not findings


# ---------------------------------------------------------------------------
# 8.3 Record integrity, versioning, repeatability, and explanation tests
# ---------------------------------------------------------------------------


def test_t_ri_01_unknown_rule_check_or_evaluation_id():
    r1 = assess_records((_valid_eval(rule_id="unknown-rule"),), (_valid_finding(rule_id="unknown-rule"),))
    r2 = assess_records((_valid_eval(check_id="unknown-check"),), (_valid_finding(check_id="unknown-check"),))
    r3 = assess_records(
        (_valid_eval(evaluation_id="metadata-field-value-validity:orientation"),),
        (_valid_finding(evaluation_id="metadata-field-value-validity:make"),),
    )
    assert r1.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r2.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r3.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_02_evaluation_finding_ids_mismatch():
    r1 = assess_records((_valid_eval(finding_ids=()),), ())
    r2 = assess_records(
        (
            _valid_eval(
                coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
                coverage_reason="Passed.",
                finding_ids=("invalid-metadata-orientation",),
            ),
        ),
        (_valid_finding(),),
    )
    r3 = assess_records(
        (
            _valid_eval(
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.FAILED.value,
                finding_ids=("invalid-metadata-orientation",),
            ),
        ),
        (_valid_finding(),),
    )
    assert r1.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r2.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r3.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_03_contradictory_duplicate_finding():
    f1 = _valid_finding()
    f2 = AssessmentFinding(
        **{**f1.to_dict(), "explanation": "Different explanation."}
    )
    result = assess_records((_valid_eval(),), (f1, f2))
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_04_mixed_unknown_or_missing_version():
    r1 = assess_records((_valid_eval(rule_set_version="PT-EA/9.9.9"),), (_valid_finding(rule_set_version="PT-EA/9.9.9"),))
    r2 = assess_records((_valid_eval(),), (_valid_finding(),), rule_set_version="PT-EA/0.9.0")
    assert r1.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r2.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_05_exact_duplicates_collapsed_deterministically():
    ev = _valid_eval()
    f = _valid_finding()
    result = assess_records((ev, ev), (f, f))
    assert result.outcome is AssessmentOutcome.NEEDS_REVIEW
    assert len(result.evaluations) == 1
    assert len(result.findings) == 1


def test_t_ri_06_contradictory_duplicate_evaluation():
    ev1 = _valid_eval()
    ev2 = _valid_eval(
        coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
        coverage_reason="Different state.",
        finding_ids=(),
    )
    result = assess_records((ev1, ev2), (_valid_finding(),))
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_07_finding_attached_to_not_applicable_or_not_evaluable():
    r1 = assess_records(
        (
            _valid_eval(
                applicability=Applicability.NOT_APPLICABLE,
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.NOT_APPLICABLE.value,
                finding_ids=(),
            ),
        ),
        (_valid_finding(),),
    )
    r2 = assess_records(
        (
            _valid_eval(
                applicability=Applicability.APPLICABLE,
                coverage_state=CoverageState.NOT_EVALUABLE,
                coverage_reason=NotEvaluableReason.FAILED.value,
                finding_ids=(),
            ),
        ),
        (_valid_finding(),),
    )
    assert r1.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r2.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize("bad_relevance", ["review", "UNKNOWN", 42])
def test_t_ri_08_invalid_relevance_values(bad_relevance):
    result = assess_records(
        (_valid_eval(),),
        (_valid_finding(relevance=bad_relevance),),  # type: ignore[arg-type]
    )
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_t_ri_09_blank_or_missing_required_field():
    bad_finding = AssessmentFinding(**{**_valid_finding().to_dict(), "title": "   "})
    result = assess_records((_valid_eval(),), (bad_finding,))
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert result.limitations


def test_t_ri_10_legacy_phase2_finding_excluded():
    legacy = Finding(
        finding_id="invalid-metadata-orientation",
        category="Metadata validity",
        title="Orientation has an invalid value",
        relevance="Review",
        observed_evidence="Stored value: '9'.",
        explanation="Invalid.",
        possible_interpretations="Malformed.",
        confidence_limitations="None.",
        recommended_next_check="Check raw tag.",
    )
    result = assess_records((), (legacy,))
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert not result.findings


def test_t_rp_01_repeatability_and_order_invariance():
    ev_make = _valid_eval(
        evaluation_id="metadata-field-value-validity:make",
        coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
        coverage_reason="Valid.",
        finding_ids=(),
    )
    ev_orient = _valid_eval()
    f_orient = _valid_finding()
    r1 = assess_records((ev_make, ev_orient), (f_orient,))
    r2 = assess_records((ev_orient, ev_make), (f_orient, f_orient))
    assert r1 == r2
    assert json.dumps(r1.to_dict(), sort_keys=True) == json.dumps(r2.to_dict(), sort_keys=True)


def test_t_ex_01_required_base_wording_and_explanations():
    lc = assess_inspection(
        _make_inspection((_field("make", "Camera make", "Canon", MetadataStatus.PRESENT),))
    )
    nr = assess_inspection(
        _make_inspection((_field("orientation", "Orientation", "9", MetadataStatus.INVALID),))
    )
    ie = assess_inspection(_make_inspection(()))

    assert BASE_WORDING[AssessmentOutcome.LOW_CONCERN] in lc.outcome_explanation
    assert BASE_WORDING[AssessmentOutcome.NEEDS_REVIEW] in nr.outcome_explanation
    assert BASE_WORDING[AssessmentOutcome.INSUFFICIENT_EVIDENCE] in ie.outcome_explanation
    for res in (lc, nr, ie):
        assert BOUNDARY_STATEMENT in res.limitations
    assert nr.findings[0].possible_interpretations
    assert nr.findings[0].recommended_next_check


def test_t_ex_02_no_numeric_scores_or_truth_verdicts():
    nr = assess_inspection(
        _make_inspection((_field("orientation", "Orientation", "9", MetadataStatus.INVALID),))
    )
    serialized = json.dumps(nr.to_dict()).lower()
    assert not re.search(r"\b(real|fake|authentic|manipulated)\b(?<!not confirm that the image is authentic)(?<!certify image authenticity)", serialized)
    for forbidden_key in ("score", "confidence", "probability", "percentage"):
        assert forbidden_key not in nr.to_dict()


def test_app_renders_evidence_assessment_tab():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    app = AppTest.from_file(str(app_path)).run()
    assert not app.exception
    tab_labels = [tab.label for tab in app.tabs]
    assert "Evidence Assessment" in tab_labels


def test_app_renders_populated_evidence_assessment_tab():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    buffer = BytesIO()
    exif = Image.Exif()
    exif[271] = "Canon"
    Image.new("RGB", (32, 24), color=(100, 120, 140)).save(buffer, format="JPEG", exif=exif)

    app_path = Path(__file__).resolve().parent.parent / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=8).run(timeout=8)
    app.file_uploader[0].set_value(("canon.jpg", buffer.getvalue(), "image/jpeg"))
    app.run(timeout=8)
    assert not app.exception

    assessment_tab = app.tabs[6]
    markdown_text = " ".join(item.value for item in assessment_tab.markdown)
    assert "Assessment outcome: LOW CONCERN" in markdown_text
    assert any(BOUNDARY_STATEMENT in item.value for item in assessment_tab.markdown)


@pytest.mark.parametrize(
    ("rule_id", "evaluation_id", "check_id"),
    [
        ("metadata-field-value-validity", "metadata-field-value-validity:unknown_key", "metadata-integrity-check"),
        ("metadata-field-value-validity", "arbitrary-eval-id", "metadata-integrity-check"),
        ("exif-decoded-dimension-comparison", "exif-decoded-dimension-comparison:extra", "metadata-consistency-check"),
        ("exif-original-digitized-time-comparison", "exif-original-digitized-time-comparison:1", "metadata-consistency-check"),
    ],
)
def test_invalid_evaluation_id_format_rejected(rule_id, evaluation_id, check_id):
    ev = _valid_eval(
        rule_id=rule_id,
        evaluation_id=evaluation_id,
        check_id=check_id,
        coverage_state=CoverageState.EVALUATED_WITHOUT_FINDING,
        coverage_reason="Passed.",
        finding_ids=(),
    )
    result = assess_records((ev,), ())
    assert result.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE


def test_unhashable_fields_in_records_do_not_raise_typeerror():
    bad_eval = _valid_eval(
        rule_id=["metadata-field-value-validity"],  # type: ignore[arg-type]
        rule_set_version={"bad": "version"},  # type: ignore[arg-type]
        check_id=["metadata-integrity-check"],  # type: ignore[arg-type]
        coverage_state=CoverageState.NOT_EVALUABLE,
        coverage_reason=["FAILED"],  # type: ignore[arg-type]
        finding_ids=(),
    )
    bad_finding = _valid_finding(
        rule_id=["metadata-field-value-validity"],  # type: ignore[arg-type]
        rule_set_version={"bad": "version"},  # type: ignore[arg-type]
        check_id=["metadata-integrity-check"],  # type: ignore[arg-type]
        finding_id=["invalid-metadata-orientation"],  # type: ignore[arg-type]
        relevance=["Review"],  # type: ignore[arg-type]
    )
    r_eval = assess_records((bad_eval,), ())
    r_finding = assess_records((_valid_eval(),), (bad_finding,))
    assert r_eval.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE
    assert r_finding.outcome is AssessmentOutcome.INSUFFICIENT_EVIDENCE

