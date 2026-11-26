"""Multi-engine metadata record merging, deduplication, and disagreement detection."""

from __future__ import annotations

from dataclasses import replace
import re
from typing import Any

from core.metadata_models import MetadataRecord


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _norm_key(text: str) -> str:
    return _NON_ALNUM.sub("", (text or "").lower())


def _canonical_identity(rec: MetadataRecord) -> tuple[str, str, int]:
    """Build a stable identity key for deduplicating equivalent observations across engines."""
    cat = _norm_key(rec.category)
    # Group structural/container vs EXIF/XMP/IPTC
    if "exif" in cat or rec.source in {"EXIF", "ExifTool"} and rec.namespace in {"IFD0", "ExifIFD", "InteropIFD", "IFD1", "EXIF"}:
        domain = "exif"
    elif "xmp" in cat:
        domain = "xmp"
    elif "iptc" in cat:
        domain = "iptc"
    elif "icc" in cat:
        domain = "icc"
    elif "jfif" in cat or "jpeg" in cat:
        domain = "jpeg"
    elif "file" in cat:
        domain = "file"
    elif "image" in cat:
        domain = "image"
    else:
        domain = cat or "other"

    tag_norm = _norm_key(rec.tag_name)
    return (domain, tag_norm, rec.instance_index)


def _norm_comparable_value(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return f"{float(val):.6g}"
    if isinstance(val, (list, tuple)):
        return ",".join(_norm_comparable_value(v) for v in val)
    return " ".join(str(val).strip().lower().split())


def _are_independent_engines(engine_a: str, engine_b: str) -> bool:
    """Avoid treating two Pillow-derived stages as independent verification."""
    a = (engine_a or "").lower()
    b = (engine_b or "").lower()
    if not a or not b or a == b:
        return False
    pillow_family = {"pillow", "image decoder"}
    if a in pillow_family and b in pillow_family:
        return False
    return True


def merge_metadata_records(
    primary_records: list[MetadataRecord] | tuple[MetadataRecord, ...],
    secondary_records: list[MetadataRecord] | tuple[MetadataRecord, ...] = (),
) -> tuple[MetadataRecord, ...]:
    """
    Merge records from internal parsers and ExifTool without losing provenance or genuine duplicates.

    - Preserves all primary records and their deterministic record_ids.
    - Enriches matching records with `discovered_by` provenance from secondary engines.
    - Records `engine_disagreement` when two independent engines report conflicting values.
    - Appends non-duplicate records (including genuine repeated instances or extra ExifTool tags).
    """
    merged: list[MetadataRecord] = []
    index_by_identity: dict[tuple[str, str, int], int] = {}

    for rec in primary_records:
        engine = rec.source_engine or rec.source
        enriched = replace(
            rec,
            source_engine=engine,
            discovered_by=rec.discovered_by or (engine,),
        )
        ident = _canonical_identity(enriched)
        idx = len(merged)
        merged.append(enriched)
        index_by_identity.setdefault(ident, idx)

    for sec in secondary_records:
        sec_engine = sec.source_engine or sec.source
        sec_enriched = replace(
            sec,
            source_engine=sec_engine,
            discovered_by=sec.discovered_by or (sec_engine,),
        )
        ident = _canonical_identity(sec_enriched)
        existing_idx = index_by_identity.get(ident)
        if existing_idx is None:
            index_by_identity[ident] = len(merged)
            merged.append(sec_enriched)
            continue

        existing = merged[existing_idx]
        existing_engine = existing.source_engine or existing.source
        combined_engines = tuple(
            dict.fromkeys([*(existing.discovered_by or (existing_engine,)), *(sec_enriched.discovered_by or (sec_engine,))])
        )

        disagreement = existing.engine_disagreement
        if _are_independent_engines(existing_engine, sec_engine):
            v1 = _norm_comparable_value(existing.raw_value)
            v2 = _norm_comparable_value(sec_enriched.raw_value)
            i1 = _norm_comparable_value(existing.interpreted_value)
            i2 = _norm_comparable_value(sec_enriched.interpreted_value)
            if v1 and v2 and v1 != v2 and i1 != i2:
                note = f"{existing_engine}={existing.interpreted_value or existing.raw_value} vs {sec_engine}={sec_enriched.interpreted_value or sec_enriched.raw_value}"
                disagreement = note[:240]

        merged[existing_idx] = replace(
            existing,
            tag_id=existing.tag_id or sec_enriched.tag_id,
            discovered_by=combined_engines,
            engine_disagreement=disagreement,
        )

    return tuple(merged)
