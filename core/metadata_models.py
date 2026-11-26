"""Immutable data models for comprehensive metadata inventory and coverage (Phase 6)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Any

from core.models import MetadataStatus


class StageCompletionState(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    EMPTY = "EMPTY"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    SKIPPED_RESOURCE_LIMIT = "SKIPPED_RESOURCE_LIMIT"


_FORMULA_CHARS = ("=", "+", "-", "@")
_LEADING_CONTROL_OR_WS = re.compile(r"^[\s\x00-\x1f\x7f]+")


def sanitize_csv_cell(value: object) -> str | int | float:
    """Neutralize spreadsheet formula-injection prefixes while keeping numeric and JSON values intact."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    stripped = _LEADING_CONTROL_OR_WS.sub("", text)
    if text.startswith(("\t", "\r", "\n")) or stripped.startswith(_FORMULA_CHARS):
        return "'" + text
    return text


@dataclass(frozen=True)
class MetadataExtractionWarning:
    """Non-fatal extraction warning or scope limitation for a stage."""

    stage_id: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stage_id": self.stage_id,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class MetadataRecord:
    """Single extracted metadata item, container property, or hierarchical node."""

    record_id: str
    source: str
    category: str
    tag_name: str
    tag_id: str | None = None
    namespace: str | None = None
    path: tuple[str, ...] = ()
    raw_value: Any = None
    interpreted_value: str = ""
    data_type: str = "string"
    status: MetadataStatus = MetadataStatus.PRESENT
    is_unknown: bool = False
    is_hierarchical: bool = False
    attributes: tuple[tuple[str, str], ...] = ()
    limitations: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "source": self.source,
            "category": self.category,
            "tag_name": self.tag_name,
            "tag_id": self.tag_id,
            "namespace": self.namespace,
            "path": list(self.path),
            "raw_value": self.raw_value,
            "interpreted_value": self.interpreted_value,
            "data_type": self.data_type,
            "status": self.status.value,
            "is_unknown": self.is_unknown,
            "is_hierarchical": self.is_hierarchical,
            "attributes": {k: v for k, v in self.attributes},
            "limitations": self.limitations,
        }


@dataclass(frozen=True)
class MetadataExtractionStage:
    """Measurable execution and coverage record for one extraction stage."""

    stage_id: str
    source_standard: str
    completion_state: StageCompletionState
    records_extracted: int
    warnings: tuple[MetadataExtractionWarning, ...] = ()
    unsupported_features: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "source_standard": self.source_standard,
            "completion_state": self.completion_state.value,
            "records_extracted": self.records_extracted,
            "warnings": [w.to_dict() for w in self.warnings],
            "unsupported_features": list(self.unsupported_features),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class MetadataExtractionCoverage:
    """Aggregated coverage, warnings, and honest limitations across all stages."""

    total_records: int
    categories_found: tuple[str, ...]
    unsupported_sources: tuple[str, ...]
    stages: tuple[MetadataExtractionStage, ...]
    warnings: tuple[MetadataExtractionWarning, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "categories_found": list(self.categories_found),
            "unsupported_sources": list(self.unsupported_sources),
            "stages": [s.to_dict() for s in self.stages],
            "warnings": [w.to_dict() for w in self.warnings],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class MetadataInventory:
    """Comprehensive non-GPS metadata inventory and measurable extraction coverage."""

    records: tuple[MetadataRecord, ...]
    coverage: MetadataExtractionCoverage
    gps_present_indicator: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "coverage": self.coverage.to_dict(),
            "gps_present_indicator": self.gps_present_indicator,
        }
