"""Phase 1 orchestration for validated properties, metadata, and SHA-256."""

from core.hashing import calculate_sha256
from core.image_info import extract_image_properties
from core.metadata import extract_metadata
from core.metadata_integrity import inspect_metadata_integrity
from core.metadata_inventory import extract_metadata_inventory
from core.models import ImageInspection
from utils.validators import validate_image_bytes


def inspect_image(file_bytes: bytes, filename: str) -> ImageInspection:
    """Validate and inspect an uploaded image without writing it to disk."""
    validated = validate_image_bytes(file_bytes, filename)
    properties = extract_image_properties(file_bytes, filename, validated=validated)
    metadata = extract_metadata(file_bytes, validated.image_format)
    findings = inspect_metadata_integrity(properties, metadata)
    inventory = extract_metadata_inventory(file_bytes, validated.image_format, properties)
    warnings = ()
    if properties.extension_mismatch:
        warnings = (
            "The filename extension does not match the detected image format. "
            "Properties are based on the file contents.",
        )
    return ImageInspection(
        properties=properties,
        metadata=metadata,
        sha256=calculate_sha256(file_bytes),
        warnings=warnings,
        findings=findings,
        inventory=inventory,
    )
