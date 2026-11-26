"""Immutable data models and provenance contracts for Phase 3.3 evidence assessment."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


RULE_SET_VERSION = "PT-EA/1.1.0"


class CoverageState(str, Enum):
    EVALUATED_WITH_FINDING = "EVALUATED_WITH_FINDING"
    EVALUATED_WITHOUT_FINDING = "EVALUATED_WITHOUT_FINDING"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Applicability(str, Enum):
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNDETERMINED = "UNDETERMINED"


class NotEvaluableReason(str, Enum):
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"
    MISSING_REQUIRED_EVIDENCE = "MISSING_REQUIRED_EVIDENCE"
    APPLICABILITY_UNKNOWN = "APPLICABILITY_UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Relevance(str, Enum):
    INFORMATIONAL = "Informational"
    REVIEW = "Review"


class AssessmentOutcome(str, Enum):
    LOW_CONCERN = "LOW CONCERN"
    NEEDS_REVIEW = "NEEDS REVIEW"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT EVIDENCE"


@dataclass(frozen=True)
class RuleEvaluation:
    """Explicit applicability, coverage, and emitted finding IDs for one rule evaluation."""

    rule_set_version: str
    rule_id: str
    evaluation_id: str
    check_id: str
    applicability: Applicability | str
    applicability_reason: str
    coverage_state: CoverageState | str
    coverage_reason: str
    finding_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_set_version": self.rule_set_version,
            "rule_id": self.rule_id,
            "evaluation_id": self.evaluation_id,
            "check_id": self.check_id,
            "applicability": (
                self.applicability.value
                if isinstance(self.applicability, Enum)
                else self.applicability
            ),
            "applicability_reason": self.applicability_reason,
            "coverage_state": (
                self.coverage_state.value
                if isinstance(self.coverage_state, Enum)
                else self.coverage_state
            ),
            "coverage_reason": self.coverage_reason,
            "finding_ids": list(self.finding_ids),
        }


@dataclass(frozen=True)
class AssessmentFinding:
    """Assessment-grade observation with full rule and evaluation provenance."""

    rule_set_version: str
    rule_id: str
    evaluation_id: str
    check_id: str
    finding_id: str
    category: str
    title: str
    relevance: str
    observed_evidence: str
    explanation: str
    possible_interpretations: str
    limitations: str
    recommended_next_check: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_set_version": self.rule_set_version,
            "rule_id": self.rule_id,
            "evaluation_id": self.evaluation_id,
            "check_id": self.check_id,
            "finding_id": self.finding_id,
            "category": self.category,
            "title": self.title,
            "relevance": self.relevance,
            "observed_evidence": self.observed_evidence,
            "explanation": self.explanation,
            "possible_interpretations": self.possible_interpretations,
            "limitations": self.limitations,
            "recommended_next_check": self.recommended_next_check,
        }


@dataclass(frozen=True)
class AssessmentResult:
    """Deterministic, non-numeric evidence assessment summary."""

    outcome: AssessmentOutcome
    outcome_explanation: str
    evaluations: tuple[RuleEvaluation, ...]
    findings: tuple[AssessmentFinding, ...]
    rule_set_version: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "outcome_explanation": self.outcome_explanation,
            "rule_set_version": self.rule_set_version,
            "evaluations": [item.to_dict() for item in self.evaluations],
            "findings": [item.to_dict() for item in self.findings],
            "limitations": list(self.limitations),
        }
