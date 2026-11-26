"""Deterministic three-state evidence assessment engine (PT-EA/1.0.0)."""

from __future__ import annotations

from typing import Iterable

from core.assessment_evaluator import evaluate_inspection
from core.assessment_models import (
    RULE_SET_VERSION,
    Applicability,
    AssessmentFinding,
    AssessmentOutcome,
    AssessmentResult,
    CoverageState,
    NotEvaluableReason,
    Relevance,
    RuleEvaluation,
)
from core.assessment_registry import (
    REGISTERED_CHECK_IDS,
    RULE_REGISTRY,
    SUPPORTED_RULE_SET_VERSIONS,
)
from core.models import Finding, ImageInspection


BASE_WORDING: dict[AssessmentOutcome, str] = {
    AssessmentOutcome.LOW_CONCERN: (
        "No registered review-level irregularities were found in the checks listed here. "
        "This does not confirm that the image is authentic or unaltered."
    ),
    AssessmentOutcome.NEEDS_REVIEW: (
        "These documented observations warrant follow-up. "
        "They do not prove editing or manipulation."
    ),
    AssessmentOutcome.INSUFFICIENT_EVIDENCE: (
        "The available checks could not support a meaningful assessment. "
        "This is not evidence that the image was altered."
    ),
}

BOUNDARY_STATEMENT = (
    "PIXELTRUTH summarizes available evidence and limitations and does not determine "
    "or certify image authenticity."
)

_APPLICABILITY_VALUES = {item.value for item in Applicability}
_COVERAGE_VALUES = {item.value for item in CoverageState}
_NOT_EVALUABLE_VALUES = {item.value for item in NotEvaluableReason}
_RELEVANCE_VALUES = {item.value for item in Relevance}

_FINDING_REQUIRED_FIELDS = (
    "rule_set_version",
    "rule_id",
    "evaluation_id",
    "check_id",
    "finding_id",
    "category",
    "title",
    "relevance",
    "observed_evidence",
    "explanation",
    "possible_interpretations",
    "limitations",
    "recommended_next_check",
)


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _enum_str(value: object) -> str | None:
    if isinstance(value, (Applicability, CoverageState, NotEvaluableReason, Relevance)):
        return value.value
    if isinstance(value, str):
        return value
    return None


def _normalize_evaluation(ev: RuleEvaluation) -> RuleEvaluation:
    return RuleEvaluation(
        rule_set_version=ev.rule_set_version,
        rule_id=ev.rule_id,
        evaluation_id=ev.evaluation_id,
        check_id=ev.check_id,
        applicability=_enum_str(ev.applicability) or "",
        applicability_reason=ev.applicability_reason,
        coverage_state=_enum_str(ev.coverage_state) or "",
        coverage_reason=ev.coverage_reason,
        finding_ids=tuple(sorted(ev.finding_ids)),
    )


def _validate_and_collapse_evaluations(
    evaluations: Iterable[object],
) -> tuple[dict[tuple[str, str], RuleEvaluation], list[str]]:
    errors: list[str] = []
    collapsed: dict[tuple[str, str], RuleEvaluation] = {}

    for item in evaluations:
        if not isinstance(item, RuleEvaluation):
            errors.append("An evaluation record is not a RuleEvaluation instance.")
            continue

        for attr in (
            "rule_set_version",
            "rule_id",
            "evaluation_id",
            "check_id",
            "applicability_reason",
            "coverage_reason",
        ):
            if not _is_non_empty_str(getattr(item, attr)):
                errors.append(f"RuleEvaluation has missing or invalid '{attr}'.")

        if not isinstance(item.rule_set_version, str) or item.rule_set_version not in SUPPORTED_RULE_SET_VERSIONS:
            errors.append(
                f"Unsupported or missing rule_set_version {item.rule_set_version!r} on evaluation {item.evaluation_id!r}."
            )

        spec = RULE_REGISTRY.get(item.rule_id) if isinstance(item.rule_id, str) else None
        if spec is None:
            errors.append(f"Unknown rule_id {item.rule_id!r} on evaluation {item.evaluation_id!r}.")
        else:
            if (
                not isinstance(item.check_id, str)
                or item.check_id not in REGISTERED_CHECK_IDS
                or item.check_id != spec.check_id
            ):
                errors.append(
                    f"Evaluation {item.evaluation_id!r} references unknown or mismatched check_id {item.check_id!r}."
                )
            if isinstance(item.evaluation_id, str) and not spec.is_valid_evaluation_id(item.evaluation_id):
                errors.append(
                    f"Evaluation {item.evaluation_id!r} does not match declared format for rule {item.rule_id!r}."
                )

        app_val = _enum_str(item.applicability)
        cov_val = _enum_str(item.coverage_state)
        if app_val not in _APPLICABILITY_VALUES:
            errors.append(f"Invalid applicability {item.applicability!r} on evaluation {item.evaluation_id!r}.")
        if cov_val not in _COVERAGE_VALUES:
            errors.append(f"Invalid coverage_state {item.coverage_state!r} on evaluation {item.evaluation_id!r}.")

        if isinstance(item.finding_ids, str) or not isinstance(item.finding_ids, (tuple, list)):
            errors.append(f"Evaluation {item.evaluation_id!r} has non-sequence finding_ids.")
        else:
            for fid in item.finding_ids:
                if not _is_non_empty_str(fid):
                    errors.append(f"Evaluation {item.evaluation_id!r} contains a blank finding_id.")

            if cov_val == CoverageState.EVALUATED_WITH_FINDING.value and len(item.finding_ids) == 0:
                errors.append(
                    f"Evaluation {item.evaluation_id!r} is EVALUATED_WITH_FINDING but has empty finding_ids."
                )
            if cov_val in {
                CoverageState.EVALUATED_WITHOUT_FINDING.value,
                CoverageState.NOT_EVALUABLE.value,
                CoverageState.NOT_APPLICABLE.value,
            } and len(item.finding_ids) > 0:
                errors.append(
                    f"Evaluation {item.evaluation_id!r} is {cov_val} but has non-empty finding_ids."
                )

        if app_val == Applicability.NOT_APPLICABLE.value and not (
            cov_val == CoverageState.NOT_APPLICABLE.value
            or (
                cov_val == CoverageState.NOT_EVALUABLE.value
                and item.coverage_reason == NotEvaluableReason.NOT_APPLICABLE.value
            )
        ):
            errors.append(
                f"Evaluation {item.evaluation_id!r} is NOT_APPLICABLE without NOT_APPLICABLE coverage."
            )
        if app_val == Applicability.UNDETERMINED.value and (
            cov_val != CoverageState.NOT_EVALUABLE.value
            or item.coverage_reason != NotEvaluableReason.APPLICABILITY_UNKNOWN.value
        ):
            errors.append(
                f"Evaluation {item.evaluation_id!r} is UNDETERMINED without NOT_EVALUABLE/APPLICABILITY_UNKNOWN coverage."
            )
        if cov_val == CoverageState.NOT_EVALUABLE.value and (
            not isinstance(item.coverage_reason, str)
            or item.coverage_reason not in _NOT_EVALUABLE_VALUES
        ):
            errors.append(
                f"Evaluation {item.evaluation_id!r} is NOT_EVALUABLE with invalid coverage_reason {item.coverage_reason!r}."
            )

        if errors:
            continue

        normalized = _normalize_evaluation(item)
        key = (normalized.rule_id, normalized.evaluation_id)
        existing = collapsed.get(key)
        if existing is not None:
            if existing != normalized:
                errors.append(
                    f"Contradictory duplicate RuleEvaluation records for {normalized.evaluation_id!r}."
                )
        else:
            collapsed[key] = normalized

    return collapsed, errors


def _validate_and_collapse_findings(
    findings: Iterable[object],
) -> tuple[dict[str, AssessmentFinding], list[str]]:
    errors: list[str] = []
    collapsed: dict[str, AssessmentFinding] = {}

    for item in findings:
        # Legacy Phase 2 Finding records lack provenance and are excluded per spec.
        if isinstance(item, Finding):
            continue
        if not isinstance(item, AssessmentFinding):
            errors.append("A finding record is not an AssessmentFinding instance.")
            continue

        missing_or_invalid = False
        for attr in _FINDING_REQUIRED_FIELDS:
            if not _is_non_empty_str(getattr(item, attr)):
                errors.append(f"AssessmentFinding {item.finding_id!r} has missing or invalid '{attr}'.")
                missing_or_invalid = True

        if not isinstance(item.rule_set_version, str) or item.rule_set_version not in SUPPORTED_RULE_SET_VERSIONS:
            errors.append(
                f"Unsupported or missing rule_set_version {item.rule_set_version!r} on finding {item.finding_id!r}."
            )

        if not isinstance(item.relevance, str) or item.relevance not in _RELEVANCE_VALUES:
            errors.append(
                f"Invalid relevance {item.relevance!r} on finding {item.finding_id!r}; expected exact 'Informational' or 'Review'."
            )

        spec = RULE_REGISTRY.get(item.rule_id) if isinstance(item.rule_id, str) else None
        if spec is None:
            errors.append(f"Unknown rule_id {item.rule_id!r} on finding {item.finding_id!r}.")
        else:
            if (
                not isinstance(item.check_id, str)
                or item.check_id not in REGISTERED_CHECK_IDS
                or item.check_id != spec.check_id
            ):
                errors.append(
                    f"Finding {item.finding_id!r} references unknown or mismatched check_id {item.check_id!r}."
                )
            if isinstance(item.evaluation_id, str) and not spec.is_valid_evaluation_id(item.evaluation_id):
                errors.append(
                    f"Finding {item.finding_id!r} references invalid evaluation_id {item.evaluation_id!r} for rule {item.rule_id!r}."
                )
            expected_rel = (
                spec.allowed_relevance_for(item.finding_id)
                if isinstance(item.finding_id, str)
                else None
            )
            if expected_rel is None or expected_rel.value != item.relevance:
                errors.append(
                    f"Finding {item.finding_id!r} conflicts with registry pattern/relevance for rule {item.rule_id!r}."
                )

        if missing_or_invalid:
            continue

        existing = collapsed.get(item.finding_id)
        if existing is not None:
            if existing != item:
                errors.append(f"Contradictory duplicate AssessmentFinding records for {item.finding_id!r}.")
        else:
            collapsed[item.finding_id] = item

    return collapsed, errors


def _cross_validate(
    evaluations: dict[tuple[str, str], RuleEvaluation],
    findings: dict[str, AssessmentFinding],
) -> list[str]:
    errors: list[str] = []

    for finding in findings.values():
        ev = evaluations.get((finding.rule_id, finding.evaluation_id))
        if ev is None:
            errors.append(
                f"Finding {finding.finding_id!r} references missing evaluation ({finding.rule_id!r}, {finding.evaluation_id!r})."
            )
            continue
        if (
            ev.rule_set_version != finding.rule_set_version
            or ev.check_id != finding.check_id
            or ev.applicability != Applicability.APPLICABLE.value
            or ev.coverage_state != CoverageState.EVALUATED_WITH_FINDING.value
            or finding.finding_id not in ev.finding_ids
        ):
            errors.append(
                f"Finding {finding.finding_id!r} provenance does not match an APPLICABLE EVALUATED_WITH_FINDING evaluation."
            )

    for ev in evaluations.values():
        for fid in ev.finding_ids:
            finding = findings.get(fid)
            if finding is None or (finding.rule_id, finding.evaluation_id) != (ev.rule_id, ev.evaluation_id):
                errors.append(
                    f"Evaluation {ev.evaluation_id!r} lists finding_id {fid!r} which does not resolve to a matching finding."
                )

    return errors


def _collect_coverage_limitations(evaluations: tuple[RuleEvaluation, ...]) -> tuple[str, ...]:
    notes: list[str] = []
    not_applicable_ids = [
        ev.evaluation_id for ev in evaluations if ev.applicability == Applicability.NOT_APPLICABLE.value
    ]
    evaluated_non_exif = any(
        ev.rule_id in {
            "image-properties-consistency",
            "container-structure-integrity",
            "embedded-xmp-integrity",
            "embedded-icc-integrity",
        }
        and ev.coverage_state in {
            CoverageState.EVALUATED_WITH_FINDING.value,
            CoverageState.EVALUATED_WITHOUT_FINDING.value,
        }
        for ev in evaluations
    )
    has_na_exif = any(
        ev.rule_id in {
            "metadata-field-value-validity",
            "exif-original-digitized-time-comparison",
            "exif-decoded-dimension-comparison",
        }
        and ev.applicability == Applicability.NOT_APPLICABLE.value
        for ev in evaluations
    )
    if has_na_exif and evaluated_non_exif:
        notes.append(
            "Some EXIF-based checks could not be performed because the required embedded metadata was unavailable. "
            "Other checks were performed using the image's available technical properties and file structure."
        )
    if not_applicable_ids:
        notes.append(
            f"Not applicable ({len(not_applicable_ids)} evaluation(s)): "
            + ", ".join(not_applicable_ids)
            + "."
        )
    for ev in evaluations:
        if (
            ev.coverage_state == CoverageState.NOT_EVALUABLE.value
            and ev.applicability != Applicability.NOT_APPLICABLE.value
        ):
            notes.append(
                f"{ev.evaluation_id} ({ev.rule_id}) was not evaluable [{ev.coverage_reason}]: {ev.applicability_reason}"
            )
    notes.append(BOUNDARY_STATEMENT)
    return tuple(notes)


def assess_records(
    evaluations: Iterable[object],
    findings: Iterable[object],
    *,
    image_validated: bool = True,
    rule_set_version: str = RULE_SET_VERSION,
) -> AssessmentResult:
    """Validate records and deterministically compute AssessmentOutcome (Rules A-D)."""
    errors: list[str] = []
    if rule_set_version not in SUPPORTED_RULE_SET_VERSIONS:
        errors.append(f"Unsupported assessment rule_set_version {rule_set_version!r}.")

    collapsed_evals, eval_errors = _validate_and_collapse_evaluations(evaluations)
    collapsed_findings, finding_errors = _validate_and_collapse_findings(findings)
    errors.extend(eval_errors)
    errors.extend(finding_errors)
    if not errors:
        errors.extend(_cross_validate(collapsed_evals, collapsed_findings))

    sorted_evals = tuple(
        sorted(collapsed_evals.values(), key=lambda item: (item.rule_id, item.evaluation_id))
    )
    sorted_findings = tuple(
        sorted(
            collapsed_findings.values(),
            key=lambda item: (item.rule_id, item.evaluation_id, item.finding_id),
        )
    )

    # Rule A — Malformed or incompatible assessment record
    if errors:
        limitations = tuple(errors) + (BOUNDARY_STATEMENT,)
        return AssessmentResult(
            outcome=AssessmentOutcome.INSUFFICIENT_EVIDENCE,
            outcome_explanation=(
                f"{BASE_WORDING[AssessmentOutcome.INSUFFICIENT_EVIDENCE]} "
                f"Record validation failed: {errors[0]}"
            ),
            evaluations=sorted_evals,
            findings=sorted_findings,
            rule_set_version=RULE_SET_VERSION,
            limitations=limitations,
        )

    coverage_limitations = _collect_coverage_limitations(sorted_evals)

    # Rule B — Registered review finding
    review_findings = [
        item for item in sorted_findings if item.relevance == Relevance.REVIEW.value
    ]
    if review_findings:
        summary_ids = ", ".join(item.finding_id for item in review_findings)
        return AssessmentResult(
            outcome=AssessmentOutcome.NEEDS_REVIEW,
            outcome_explanation=(
                f"{BASE_WORDING[AssessmentOutcome.NEEDS_REVIEW]} "
                f"Triggered by review finding(s): {summary_ids}."
            ),
            evaluations=sorted_evals,
            findings=sorted_findings,
            rule_set_version=RULE_SET_VERSION,
            limitations=coverage_limitations,
        )

    # Rule C — LOW CONCERN
    has_substantive = any(
        RULE_REGISTRY[ev.rule_id].substantive_coverage
        and ev.evaluation_id != "metadata-field-value-validity:software"
        and ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
        for ev in sorted_evals
    )
    critical_applicable_incomplete = any(
        RULE_REGISTRY[ev.rule_id].coverage_critical
        and ev.applicability == Applicability.APPLICABLE.value
        and ev.coverage_state
        not in {
            CoverageState.EVALUATED_WITH_FINDING.value,
            CoverageState.EVALUATED_WITHOUT_FINDING.value,
        }
        for ev in sorted_evals
    )
    critical_undetermined = any(
        RULE_REGISTRY[ev.rule_id].coverage_critical
        and ev.applicability == Applicability.UNDETERMINED.value
        for ev in sorted_evals
    )

    if (
        image_validated
        and has_substantive
        and not critical_applicable_incomplete
        and not critical_undetermined
    ):
        evaluated_count = sum(
            1
            for ev in sorted_evals
            if ev.coverage_state == CoverageState.EVALUATED_WITHOUT_FINDING.value
        )
        return AssessmentResult(
            outcome=AssessmentOutcome.LOW_CONCERN,
            outcome_explanation=(
                f"{BASE_WORDING[AssessmentOutcome.LOW_CONCERN]} "
                f"Completed {evaluated_count} applicable evaluation(s) with substantive coverage."
            ),
            evaluations=sorted_evals,
            findings=sorted_findings,
            rule_set_version=RULE_SET_VERSION,
            limitations=coverage_limitations,
        )

    # Rule D — INSUFFICIENT EVIDENCE fallback
    evaluated_count = sum(
        1
        for ev in sorted_evals
        if ev.coverage_state in {
            CoverageState.EVALUATED_WITH_FINDING.value,
            CoverageState.EVALUATED_WITHOUT_FINDING.value,
        }
    )
    reasons: list[str] = []
    if not image_validated:
        reasons.append("image validation/decoding did not succeed")
    if not has_substantive:
        if evaluated_count > 0:
            reasons.append(
                f"{evaluated_count} technical/structural check(s) completed, but no substantive embedded-metadata evaluation completed"
            )
        else:
            reasons.append("no substantive rule evaluation completed")
    if critical_applicable_incomplete:
        reasons.append("a coverage-critical rule was not evaluable")
    if critical_undetermined:
        reasons.append("a coverage-critical rule had undetermined applicability")
    reason_text = "; ".join(reasons) if reasons else "insufficient evaluation coverage"

    return AssessmentResult(
        outcome=AssessmentOutcome.INSUFFICIENT_EVIDENCE,
        outcome_explanation=(
            f"{BASE_WORDING[AssessmentOutcome.INSUFFICIENT_EVIDENCE]} "
            f"Coverage limitation: {reason_text}."
        ),
        evaluations=sorted_evals,
        findings=sorted_findings,
        rule_set_version=RULE_SET_VERSION,
        limitations=coverage_limitations,
    )


def assess_inspection(inspection: ImageInspection) -> AssessmentResult:
    """Evaluate a validated ImageInspection and produce an AssessmentResult."""
    evaluations, findings = evaluate_inspection(inspection)
    image_validated = inspection.properties.width > 0 and inspection.properties.height > 0
    return assess_records(evaluations, findings, image_validated=image_validated)
