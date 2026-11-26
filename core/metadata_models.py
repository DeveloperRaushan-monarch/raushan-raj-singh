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


class ExtractionStatus(str, Enum):
    EXTRACTED = "EXTRACTED"
    PARTIALLY_EXTRACTED = "PARTIALLY_EXTRACTED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    MALFORMED = "MALFORMED"
    EXTRACTION_ERROR = "EXTRACTION_ERROR"


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
    display_name: str = ""
    group: str = ""
    source_engine: str = ""
    source_container: str = ""
    unit: str | None = None
    extraction_status: str = ""
    instance_index: int = 0
    confidence_method: str | None = None
    discovered_by: tuple[str, ...] = ()
    engine_disagreement: str | None = None

    def to_dict(self) -> dict[str, Any]:
        eff_engine = self.source_engine or self.source
        eff_discovered = list(self.discovered_by) if self.discovered_by else [eff_engine]
        eff_ext_status = self.extraction_status or (
            ExtractionStatus.EXTRACTED.value
            if self.status is MetadataStatus.PRESENT
            else ExtractionStatus.UNAVAILABLE.value
            if self.status in {MetadataStatus.MISSING, MetadataStatus.UNAVAILABLE}
            else ExtractionStatus.UNSUPPORTED.value
            if self.status is MetadataStatus.UNSUPPORTED
            else ExtractionStatus.MALFORMED.value
        )
        return {
            "record_id": self.record_id,
            "source": self.source,
            "category": self.category,
            "tag_name": self.tag_name,
            "display_name": self.display_name or self.tag_name,
            "tag_id": self.tag_id,
            "group": self.group or self.category,
            "namespace": self.namespace,
            "path": list(self.path),
            "raw_value": self.raw_value,
            "interpreted_value": self.interpreted_value,
            "data_type": self.data_type,
            "unit": self.unit,
            "status": self.status.value,
            "extraction_status": eff_ext_status,
            "is_unknown": self.is_unknown,
            "is_hierarchical": self.is_hierarchical,
            "attributes": {k: v for k, v in self.attributes},
            "limitations": self.limitations,
            "source_engine": eff_engine,
            "source_container": self.source_container or (self.path[0] if self.path else self.source),
            "instance_index": self.instance_index,
            "confidence_method": self.confidence_method,
            "discovered_by": eff_discovered,
            "engine_disagreement": self.engine_disagreement,
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
    engine_name: str = ""
    engine_version: str | None = None
    availability: str = "Available"
    duration_ms: float | None = None
    errors: tuple[str, ...] = ()
    skipped_sections: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "source_standard": self.source_standard,
            "completion_state": self.completion_state.value,
            "records_extracted": self.records_extracted,
            "warnings": [w.to_dict() for w in self.warnings],
            "unsupported_features": list(self.unsupported_features),
            "limitations": list(self.limitations),
            "engine_name": self.engine_name or self.source_standard,
            "engine_version": self.engine_version,
            "availability": self.availability,
            "duration_ms": round(self.duration_ms, 2) if self.duration_ms is not None else None,
            "errors": list(self.errors),
            "skipped_sections": list(self.skipped_sections),
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
    format_capability: dict[str, Any] | None = None
    file_signature: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "categories_found": list(self.categories_found),
            "unsupported_sources": list(self.unsupported_sources),
            "stages": [s.to_dict() for s in self.stages],
            "warnings": [w.to_dict() for w in self.warnings],
            "limitations": list(self.limitations),
            "format_capability": self.format_capability,
            "file_signature": self.file_signature,
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
