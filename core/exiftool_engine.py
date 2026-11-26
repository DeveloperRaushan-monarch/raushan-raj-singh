"""Cross-platform ExifTool discovery and safe subprocess JSON extraction."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any

from core.metadata_models import MetadataExtractionWarning, MetadataRecord
from core.models import MetadataStatus


DEFAULT_EXIFTOOL_TIMEOUT_SECONDS = 15.0
MAX_EXIFTOOL_BYTES = 50 * 1024 * 1024
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ExifToolStatus:
    available: bool
    executable_path: str | None = None
    version: str | None = None
    discovery_method: str = "unavailable"
    reason: str = "ExifTool executable was not found."

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "executable_path": self.executable_path,
            "version": self.version,
            "discovery_method": self.discovery_method,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ExifToolExtractionResult:
    status: ExifToolStatus
    execution_status: str
    duration_ms: float
    records: tuple[MetadataRecord, ...] = ()
    gps_present_indicator: bool = False
    warnings: tuple[MetadataExtractionWarning, ...] = ()
    error: str | None = None


def _candidate_paths(configured_path: str | None = None) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if configured_path:
        candidates.append((configured_path, "configured"))
    env_path = os.environ.get("PIXELTRUTH_EXIFTOOL_PATH", "").strip()
    if env_path:
        candidates.append((env_path, "env"))

    which_path = shutil.which("exiftool")
    if which_path:
        candidates.append((which_path, "PATH"))

    if os.name == "nt":
        bundled = _PROJECT_ROOT / "bin" / "windows" / "exiftool.exe"
        candidates.extend(
            [
                (str(bundled), "bundled"),
                (r"C:\Program Files\ExifTool\exiftool.exe", "standard-install"),
                (r"C:\ExifTool\exiftool.exe", "standard-install"),
            ]
        )
    else:
        bundled = _PROJECT_ROOT / "bin" / "macos" / "exiftool"
        candidates.extend(
            [
                (str(bundled), "bundled"),
                ("/usr/local/bin/exiftool", "standard-install"),
                ("/opt/homebrew/bin/exiftool", "standard-install"),
                ("/usr/bin/exiftool", "standard-install"),
            ]
        )
    return candidates


def discover_exiftool(configured_path: str | None = None) -> ExifToolStatus:
    """Discover an ExifTool executable without requiring Homebrew."""
    seen: set[str] = set()
    for raw_path, method in _candidate_paths(configured_path):
        if not raw_path or raw_path in seen:
            continue
        seen.add(raw_path)
        exe = Path(raw_path)
        if not exe.is_file():
            continue
        try:
            proc = subprocess.run(
                [str(exe), "-ver"],
                capture_output=True,
                text=True,
                timeout=5.0,
                shell=False,
                check=False,
            )
            if proc.returncode == 0:
                version = proc.stdout.strip().splitlines()[0].strip() if proc.stdout.strip() else "unknown"
                return ExifToolStatus(
                    available=True,
                    executable_path=str(exe),
                    version=version,
                    discovery_method=method,
                    reason="ExifTool executable verified.",
                )
        except (OSError, subprocess.SubprocessError):
            continue

    return ExifToolStatus(
        available=False,
        executable_path=None,
        version=None,
        discovery_method="unavailable",
        reason="ExifTool is not installed or not configured; using internal parsers.",
    )


def _group_to_category(group: str, tag_name: str) -> str:
    g = group.lower()
    t = tag_name.lower()
    if g in {"jfif", "app0"}:
        return "JPEG / JFIF Information"
    if g in {"file", "system"}:
        return "File Information"
    if g in {"icc_profile", "icc"}:
        return "ICC Color Profile"
    if g == "xmp" or g.startswith("xmp-"):
        return "XMP Metadata"
    if g == "iptc":
        return "IPTC Metadata"
    if g in {"makernotes", "canon", "nikon", "sony", "apple", "samsung", "fuji", "olympus", "panasonic"}:
        return "Camera and Lens"
    if any(k in t for k in ("make", "model", "lens", "focal", "aperture", "fnumber", "exposure", "iso", "shutter", "flash")):
        return "Camera and Lens"
    if g in {"png", "png-pHYs".lower(), "png-text".lower()}:
        return "PNG Structure"
    if g in {"riff", "webp"}:
        return "WebP Structure"
    if g in {"gif"}:
        return "GIF / Animation"
    if g in {"ifd0", "exififd", "interopifd", "ifd1", "exif"}:
        return "EXIF Metadata"
    if g in {"composite"}:
        return "Image Information"
    return "Other Container Metadata"


def _infer_dtype(val: Any) -> str:
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "float"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return "string"


def _safe_interp(val: Any) -> str:
    if val is None:
        return "Not interpreted"
    if isinstance(val, dict):
        if "val" in val:
            return str(val["val"])
        text = json.dumps(val, ensure_ascii=False)
        return text[:200] + ("..." if len(text) > 200 else "")
    if isinstance(val, list):
        text = ", ".join(str(x) for x in val[:16])
        if len(val) > 16:
            text += f" (+{len(val) - 16} more)"
        return text
    text = str(val)
    return text[:240] + ("..." if len(text) > 240 else "")


def run_exiftool(
    file_bytes: bytes,
    filename: str = "upload.bin",
    *,
    configured_path: str | None = None,
    timeout_seconds: float = DEFAULT_EXIFTOOL_TIMEOUT_SECONDS,
) -> ExifToolExtractionResult:
    """Safely invoke ExifTool via subprocess on a temporary file and parse JSON output."""
    t0 = time.monotonic()
    status = discover_exiftool(configured_path)
    if not status.available or not status.executable_path:
        return ExifToolExtractionResult(
            status=status,
            execution_status="UNAVAILABLE",
            duration_ms=(time.monotonic() - t0) * 1000.0,
        )

    if len(file_bytes) > MAX_EXIFTOOL_BYTES:
        return ExifToolExtractionResult(
            status=status,
            execution_status="SKIPPED_RESOURCE_LIMIT",
            duration_ms=(time.monotonic() - t0) * 1000.0,
            warnings=(MetadataExtractionWarning("exiftool", "SIZE_LIMIT", "File exceeded ExifTool size limit."),),
        )

    suffix = Path(filename or "upload.bin").suffix
    safe_suffix = suffix if suffix.isalnum() or (suffix.startswith(".") and suffix[1:].isalnum()) else ".bin"
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="pt_et_", suffix=safe_suffix, delete=False) as tf:
            tf.write(file_bytes)
            tmp_path = tf.name

        proc = subprocess.run(
            [status.executable_path, "-json", "-G1", "-a", "-s", "-struct", "-D", tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExifToolExtractionResult(
            status=status,
            execution_status="TIMEOUT",
            duration_ms=(time.monotonic() - t0) * 1000.0,
            warnings=(MetadataExtractionWarning("exiftool", "EXIFTOOL_TIMEOUT", f"ExifTool timed out after {timeout_seconds}s."),),
            error=f"ExifTool timed out after {timeout_seconds}s.",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ExifToolExtractionResult(
            status=status,
            execution_status="FAILED",
            duration_ms=(time.monotonic() - t0) * 1000.0,
            error=str(exc),
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    duration_ms = (time.monotonic() - t0) * 1000.0
    if proc.returncode != 0 and not proc.stdout.strip():
        err_msg = (proc.stderr or f"ExifTool exited with code {proc.returncode}").strip()
        return ExifToolExtractionResult(
            status=status,
            execution_status="FAILED",
            duration_ms=duration_ms,
            error=err_msg[:300],
        )

    try:
        parsed = json.loads(proc.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        return ExifToolExtractionResult(
            status=status,
            execution_status="FAILED",
            duration_ms=duration_ms,
            error=f"Malformed JSON from ExifTool: {exc}",
        )

    if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
        return ExifToolExtractionResult(
            status=status,
            execution_status="EMPTY",
            duration_ms=duration_ms,
        )

    obj = parsed[0]
    records: list[MetadataRecord] = []
    gps_present = False
    seen_counts: dict[tuple[str, str], int] = {}

    # Skip synthetic filesystem/temp-path tags from ExifTool
    _SKIP_KEYS = {
        "SourceFile",
        "System:FileName",
        "System:Directory",
        "System:FileModifyDate",
        "System:FileAccessDate",
        "System:FileInodeChangeDate",
        "System:FilePermissions",
    }

    for full_key, val in obj.items():
        if full_key in _SKIP_KEYS:
            continue
        if ":" in full_key:
            group, tag_name = full_key.split(":", 1)
        else:
            group, tag_name = "ExifTool", full_key

        if group.lower() == "gps" or tag_name.lower().startswith("gps"):
            gps_present = True
            continue

        instance_idx = seen_counts.get((group, tag_name), 0)
        seen_counts[(group, tag_name)] = instance_idx + 1

        raw_val = val
        tag_id: str | None = None
        if isinstance(val, dict) and "id" in val and "val" in val:
            tag_id = str(val["id"])
            raw_val = val["val"]

        records.append(
            MetadataRecord(
                record_id=f"exiftool:{group}:{tag_name}:{instance_idx}",
                source="ExifTool",
                category=_group_to_category(group, tag_name),
                tag_name=tag_name,
                tag_id=tag_id,
                namespace=group,
                path=("ExifTool", group, tag_name),
                raw_value=raw_val,
                interpreted_value=_safe_interp(val),
                data_type=_infer_dtype(raw_val),
                status=MetadataStatus.PRESENT,
                is_hierarchical=isinstance(raw_val, (dict, list)),
                display_name=tag_name,
                group=group,
                source_engine="ExifTool",
                source_container=group,
                extraction_status="EXTRACTED",
                instance_index=instance_idx,
                confidence_method="ExifTool subprocess JSON",
                discovered_by=("ExifTool",),
            )
        )

    return ExifToolExtractionResult(
        status=status,
        execution_status="COMPLETED" if records else "EMPTY",
        duration_ms=duration_ms,
        records=tuple(records),
        gps_present_indicator=gps_present,
    )
