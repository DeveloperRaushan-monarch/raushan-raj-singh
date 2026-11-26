"""Versioned rule registry for PIXELTRUTH Evidence Assessment (PT-EA/1.0.0)."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from core.assessment_models import RULE_SET_VERSION, Relevance
from core.metadata import FIELD_SPECS


SUPPORTED_RULE_SET_VERSIONS: frozenset[str] = frozenset({RULE_SET_VERSION})

FIELD_VALIDATION_KINDS: Mapping[str, str] = MappingProxyType(
    {key: validation_kind for key, _, _, validation_kind in FIELD_SPECS}
)
REGISTERED_FIELD_KEYS: tuple[str, ...] = tuple(key for key, _, _, _ in FIELD_SPECS)


@dataclass(frozen=True)
class RuleSpec:
    """Authoritative specification for one registered evidence assessment rule."""

    rule_id: str
    check_id: str
    applicability: str
    coverage_critical: bool
    coverage_critical_justification: str
    deterministic_predicate: str
    eligible_evidence: str
    limitations: str
    test_requirements: str
    finding_id_patterns: tuple[str, ...]
    finding_relevance: Mapping[str, Relevance]
    substantive_coverage: bool
    substantive_coverage_condition: str

    def allowed_relevance_for(self, finding_id: str) -> Relevance | None:
        """Return the exact registered Relevance for a finding_id, or None if unmatched."""
        if self.rule_id == "metadata-field-value-validity":
            prefix = "invalid-metadata-"
            if finding_id.startswith(prefix):
                field_key = finding_id[len(prefix) :]
                if field_key in FIELD_VALIDATION_KINDS:
                    return Relevance.REVIEW
            return None
        return self.finding_relevance.get(finding_id)

    def is_valid_evaluation_id(self, evaluation_id: str) -> bool:
        """Return True only when evaluation_id matches the rule's declared format."""
        if self.rule_id == "metadata-field-value-validity":
            prefix = "metadata-field-value-validity:"
            if not evaluation_id.startswith(prefix):
                return False
            field_key = evaluation_id[len(prefix) :]
            return field_key in FIELD_VALIDATION_KINDS
        return evaluation_id == self.rule_id


RULE_REGISTRY: Mapping[str, RuleSpec] = MappingProxyType(
    {
        "metadata-field-value-validity": RuleSpec(
            rule_id="metadata-field-value-validity",
            check_id="metadata-integrity-check",
            applicability=(
                "Produces one RuleEvaluation per registered field-key with "
                "evaluation_id = metadata-field-value-validity:<field-key>. "
                "APPLICABLE when a supported parser provides a value/status and a "
                "documented field-specific format/range validator exists. "
                "NOT_APPLICABLE when the field is MISSING or outside the registered "
                "validator scope. UNDETERMINED when parser support/applicability is "
                "UNSUPPORTED or UNAVAILABLE."
            ),
            coverage_critical=False,
            coverage_critical_justification="Optional metadata values may be absent.",
            deterministic_predicate=(
                "Evaluate only the registered field's parsed value and its field-specific "
                "validator. INVALID under that validator emits a finding; valid PRESENT "
                "value emits none. MISSING, UNSUPPORTED, or UNAVAILABLE values do not emit "
                "invalid-value findings."
            ),
            eligible_evidence=(
                "Registered EXIF MetadataField entries from FIELD_SPECS with statuses "
                "PRESENT, INVALID, MISSING, UNSUPPORTED, or UNAVAILABLE."
            ),
            limitations=(
                "Invalidity shows only that a stored value failed the named check; "
                "it does not show cause or intent."
            ),
            test_requirements=(
                "Valid, invalid, missing, unsupported, unavailable, boundary values, "
                "ID/provenance, explanation, and repeatability."
            ),
            finding_id_patterns=("invalid-metadata-<field-key>",),
            finding_relevance=MappingProxyType({"invalid-metadata-*": Relevance.REVIEW}),
            substantive_coverage=True,
            substantive_coverage_condition=(
                "A no-finding evaluation is substantive only when an actual PRESENT "
                "value with a defined field-specific constraint was tested, excluding "
                "software tags alone (metadata-field-value-validity:software)."
            ),
        ),
        "exif-original-digitized-time-comparison": RuleSpec(
            rule_id="exif-original-digitized-time-comparison",
            check_id="metadata-consistency-check",
            applicability=(
                "Singleton evaluation (evaluation_id = exif-original-digitized-time-comparison). "
                "APPLICABLE when both EXIF DateTimeOriginal and DateTimeDigitized are PRESENT "
                "(or INVALID/unparseable, yielding NOT_EVALUABLE with MISSING_REQUIRED_EVIDENCE). "
                "NOT_APPLICABLE when either field is MISSING. UNDETERMINED when either value "
                "is UNSUPPORTED or UNAVAILABLE."
            ),
            coverage_critical=False,
            coverage_critical_justification=(
                "Capture and digitized timestamps are optional and describe potentially "
                "distinct events."
            ),
            deterministic_predicate=(
                "Compare the two parsed values only to describe whether they differ. "
                "Emit an Informational observation when unequal; emit no finding when equal."
            ),
            eligible_evidence=(
                "EXIF datetime_original and datetime_digitized MetadataField entries."
            ),
            limitations=(
                "A difference alone establishes neither an impossible timeline nor alteration. "
                "This rule never supplies substantive coverage."
            ),
            test_requirements=(
                "Equal/different values, missing, unsupported, unavailable, "
                "malformed/unparseable values, relevance, non-triggering outcome, "
                "explanation, and repeatability."
            ),
            finding_id_patterns=("timestamp-original-digitized-differ",),
            finding_relevance=MappingProxyType(
                {"timestamp-original-digitized-differ": Relevance.INFORMATIONAL}
            ),
            substantive_coverage=False,
            substantive_coverage_condition="Never supplies substantive coverage.",
        ),
        "exif-decoded-dimension-comparison": RuleSpec(
            rule_id="exif-decoded-dimension-comparison",
            check_id="metadata-consistency-check",
            applicability=(
                "Singleton evaluation (evaluation_id = exif-decoded-dimension-comparison). "
                "APPLICABLE when EXIF pixel_x_dimension and pixel_y_dimension are both PRESENT "
                "(or unparseable, yielding NOT_EVALUABLE) and validated decoded raster "
                "dimensions are available. NOT_APPLICABLE when either required EXIF dimension "
                "field is MISSING. UNDETERMINED when parser support or orientation "
                "interpretation needed for comparison cannot be established (UNSUPPORTED/UNAVAILABLE)."
            ),
            coverage_critical=True,
            coverage_critical_justification=(
                "When EXIF pixel dimensions are present or parser support is undetermined, "
                "reliable comparison against decoded raster dimensions is required before "
                "reporting LOW CONCERN."
            ),
            deterministic_predicate=(
                "Compare EXIF pixel dimensions with decoded raster dimensions. "
                "Orientations 1-4: require direct (width, height) equality; swapped-only emits Review. "
                "Orientations 5-8: accept direct (width, height) or swapped (height, width); otherwise Review. "
                "Orientation MISSING: direct equality passes; swapped-only is NOT_EVALUABLE "
                "(MISSING_REQUIRED_EVIDENCE); any other mismatch emits Review. "
                "Orientation INVALID/unrecognized: direct equality passes; any non-direct match "
                "is NOT_EVALUABLE (MISSING_REQUIRED_EVIDENCE). Malformed/unparseable EXIF dimensions: "
                "NOT_EVALUABLE (MISSING_REQUIRED_EVIDENCE)."
            ),
            eligible_evidence=(
                "EXIF pixel_x_dimension, pixel_y_dimension, optional orientation MetadataField "
                "entries, and validated ImageProperties (width, height)."
            ),
            limitations=(
                "A mismatch establishes disagreement between stored and decoded dimensions only; "
                "stale metadata, resizing, or format/orientation handling may explain it."
            ),
            test_requirements=(
                "Direct match/mismatch, orientations 1-4 and 5-8, swapped dimensions with and without "
                "orientation, missing/invalid orientation, malformed dimensions, coverage-critical "
                "behavior, explanation, and repeatability."
            ),
            finding_id_patterns=("exif-pixel-dimensions-differ",),
            finding_relevance=MappingProxyType(
                {"exif-pixel-dimensions-differ": Relevance.REVIEW}
            ),
            substantive_coverage=True,
            substantive_coverage_condition=(
                "An equal comparison (EVALUATED_WITHOUT_FINDING) qualifies as substantive coverage."
            ),
        ),
    }
)

REGISTERED_CHECK_IDS: frozenset[str] = frozenset(
    spec.check_id for spec in RULE_REGISTRY.values()
)
