"""Explainable metadata availability and validity findings."""

from core.metadata_consistency import inspect_metadata_consistency
from core.models import Finding, ImageProperties, MetadataField, MetadataStatus


def inspect_metadata_integrity(
    properties: ImageProperties, fields: tuple[MetadataField, ...]
) -> tuple[Finding, ...]:
    """Create structured findings without treating missing metadata as proof."""
    findings: list[Finding] = []
    missing = [field.label for field in fields if field.status is MetadataStatus.MISSING]
    invalid = [field for field in fields if field.status is MetadataStatus.INVALID]
    unsupported = [field.label for field in fields if field.status is MetadataStatus.UNSUPPORTED]
    unavailable = [field.label for field in fields if field.status is MetadataStatus.UNAVAILABLE]

    if missing:
        findings.append(
            Finding(
                finding_id="common-metadata-fields-missing",
                category="Metadata availability",
                title="Some common metadata fields are missing",
                relevance="Informational",
                observed_evidence="Missing fields: " + ", ".join(missing) + ".",
                explanation="These fields were not present in the metadata examined by the current parser.",
                possible_interpretations="The image may not have recorded these fields, or an editing/export workflow may have omitted them.",
                confidence_limitations="Missing metadata alone does not show that data was deliberately removed or that the image was changed.",
                recommended_next_check="Review the fields that are present and seek an independent source if these values are important.",
            )
        )

    for field in invalid:
        findings.append(
            Finding(
                finding_id=f"invalid-metadata-{field.key}",
                category="Metadata validity",
                title=f"{field.label} has an invalid value",
                relevance="Review",
                observed_evidence=f"Stored value: {field.value!r}.",
                explanation=field.note or "The value did not pass the field's basic format/range check.",
                possible_interpretations="The value may be malformed, outside the defined range, or encoded in an unrecognized form.",
                confidence_limitations="A value check does not identify how the value became invalid.",
                recommended_next_check="Compare the raw tag with another metadata reader or the source device record.",
            )
        )

    if unsupported:
        findings.append(
            Finding(
                finding_id="metadata-types-unsupported",
                category="Analysis coverage",
                title="Some metadata types were not inspected",
                relevance="Informational",
                observed_evidence="Unsupported types: " + ", ".join(unsupported) + ".",
                explanation="The current parser does not inspect these metadata types.",
                possible_interpretations="Relevant information could be present in a type that this phase does not parse.",
                confidence_limitations="An unsupported type must not be treated as missing or empty.",
                recommended_next_check="Use a reader that supports the listed metadata types if they matter to the review.",
            )
        )

    if unavailable:
        findings.append(
            Finding(
                finding_id="metadata-parser-unavailable",
                category="Analysis coverage",
                title="Some metadata fields could not be read",
                relevance="Informational",
                observed_evidence="Unavailable fields: " + ", ".join(unavailable) + ".",
                explanation="The metadata parser could not return values for these fields.",
                possible_interpretations="The metadata may be malformed, encoded in an unsupported way, or inaccessible to the parser.",
                confidence_limitations="Parser failure is not evidence that the metadata was removed or altered.",
                recommended_next_check="Try a compatible metadata reader and preserve the original file bytes.",
            )
        )

    findings.extend(inspect_metadata_consistency(properties, fields))
    return tuple(findings)
