"""Comprehensive tests for Phase 6C metadata inventory, coverage, and safety."""

from __future__ import annotations

from fractions import Fraction
from io import BytesIO
import json
import struct

from PIL import ExifTags, Image, ImageCms, PngImagePlugin
from PIL.TiffImagePlugin import IFDRational
import pytest

from core.analysis import inspect_image
from core.assessment_engine import assess_inspection
from core.assessment_models import AssessmentOutcome
from core.metadata_inventory import MAX_BINARY_HEX_BYTES, extract_metadata_inventory
from core.metadata_models import StageCompletionState, sanitize_csv_cell
from core.models import MetadataStatus
from core.xmp import XMP_JPEG_EXTENDED_HEADER, XMP_JPEG_HEADER


def _build_iptc_app13(datasets: list[tuple[int, int, bytes]]) -> bytes:
    iim = bytearray()
    for rec, ds, val in datasets:
        iim.extend(b"\x1c" + bytes([rec, ds]) + len(val).to_bytes(2, "big") + val)
    if len(iim) % 2:
        iim.append(0)
    resource = b"8BIM\x04\x04\x00\x00" + len(iim).to_bytes(4, "big") + bytes(iim)
    return b"Photoshop 3.0\x00" + resource


def _inject_jpeg_app_segments(jpeg_bytes: bytes, segments: list[tuple[int, bytes]]) -> bytes:
    assert jpeg_bytes.startswith(b"\xff\xd8")
    out = bytearray(b"\xff\xd8")
    for marker, payload in segments:
        seg_len = len(payload) + 2
        out.extend(bytes([0xFF, marker]) + seg_len.to_bytes(2, "big") + payload)
    out.extend(jpeg_bytes[2:])
    return bytes(out)


def _rich_jpeg_bytes() -> bytes:
    exif = Image.Exif()
    exif[271] = "Canon"
    exif[272] = "EOS R5"
    exif[315] = "Jane Doe"
    exif[33432] = "Copyright 2026"
    exif[305] = "Darktable 4.6"
    exif[274] = 1
    exif[0x9999] = "UnknownCustomExifValue"  # Unmapped numeric tag in IFD0
    exif_ifd = exif.get_ifd(ExifTags.IFD.Exif)
    exif_ifd[33434] = IFDRational(1, 125)
    exif_ifd[33437] = IFDRational(28, 10)
    exif_ifd[37386] = IFDRational(50, 1)
    exif_ifd[34855] = 400
    exif_ifd[36867] = "2026:11:25 12:00:00"
    exif_ifd[42035] = "Canon"
    exif_ifd[42036] = "RF 50mm F1.2L"
    exif_ifd[0x927C] = b"MAKERNOTE_PROPRIETARY_" + (b"\xAB" * 80)  # Undecoded MakerNote blob
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
    }

    icc_profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    buf = BytesIO()
    Image.new("RGB", (40, 30), color=(90, 120, 150)).save(
        buf, format="JPEG", exif=exif, icc_profile=icc_profile
    )

    xmp_xml = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:dc="http://purl.org/dc/elements/1.1/"'
        b' xmlns:xmp="http://ns.adobe.com/xap/1.0/"'
        b' xmlns:custom="http://example.org/custom/1.0/">'
        b'<rdf:Description rdf:about="" xmp:CreatorTool="Lightroom">'
        b'<dc:title><rdf:Alt><rdf:li xml:lang="en">Sample Title</rdf:li></rdf:Alt></dc:title>'
        b'<dc:subject><rdf:Bag><rdf:li>forensics</rdf:li><rdf:li>test</rdf:li></rdf:Bag></dc:subject>'
        b'<custom:CaseRef>CASE-42</custom:CaseRef>'
        b'</rdf:Description></rdf:RDF></x:xmpmeta>'
    )
    iptc_payload = _build_iptc_app13(
        [
            (1, 90, b"\x1b%G"),
            (2, 105, "Headline Unicode café".encode("utf-8")),
            (2, 15, b"SCI"),
            (2, 40, b"Handle with care"),
            (2, 115, b"Lab Archive"),
            (2, 250, b"UnmappedDatasetValue"),
        ]
    )
    return _inject_jpeg_app_segments(
        buf.getvalue(),
        [(0xE1, XMP_JPEG_HEADER + xmp_xml), (0xED, iptc_payload)],
    )


def test_csv_formula_injection_neutralized_while_json_preserves_original():
    # Actual numeric values (including negative int/float) remain numeric
    assert sanitize_csv_cell(-1) == -1
    assert isinstance(sanitize_csv_cell(-1), int)
    assert sanitize_csv_cell(-3.5) == -3.5
    assert isinstance(sanitize_csv_cell(-3.5), float)
    assert sanitize_csv_cell(42) == 42
    assert sanitize_csv_cell(True) == "True"
    assert sanitize_csv_cell(False) == "False"

    for dangerous in (
        "=CMD()",
        "+SUM(1,2)",
        "-1+1",
        "@SUM(A1)",
        " =CMD()",
        "\t=1",
        "\r=1",
        "\n=CMD()",
        "\x00=CMD()",
    ):
        sanitized = sanitize_csv_cell(dangerous)
        assert isinstance(sanitized, str)
        assert sanitized.startswith("'")
        assert sanitized[1:] == dangerous
    assert sanitize_csv_cell("normal text") == "normal text"


def test_nested_xmp_gps_elements_and_attributes_excluded():
    buf = BytesIO()
    Image.new("RGB", (12, 12), color="white").save(buf, format="JPEG")
    nested_gps_xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:custom="http://example.org/custom/1.0/"'
        b' xmlns:exif="http://ns.adobe.com/exif/1.0/">'
        b'<rdf:Description custom:gpsLocation="37.77,-122.41">'
        b'<custom:Event>'
        b'<custom:Action>saved</custom:Action>'
        b'<exif:GPSLatitude>37,46.2N</exif:GPSLatitude>'
        b'<custom:gpsLongitude>122,24.6W</custom:gpsLongitude>'
        b'</custom:Event>'
        b'</rdf:Description></rdf:RDF></x:xmpmeta>'
    )
    jpeg = _inject_jpeg_app_segments(buf.getvalue(), [(0xE1, XMP_JPEG_HEADER + nested_gps_xmp)])
    inspection = inspect_image(jpeg, "nested_gps.jpg")
    inv = inspection.inventory
    assert inv is not None
    assert inv.gps_present_indicator is True

    serialized = json.dumps(inv.to_dict())
    assert "37,46.2N" not in serialized
    assert "122,24.6W" not in serialized
    assert "37.77,-122.41" not in serialized
    assert any(r.tag_name == "Action" and r.interpreted_value == "saved" for r in inv.records)


def test_rich_jpeg_extracts_all_standards_rationals_makernotes_and_unknown_tags():
    raw = _rich_jpeg_bytes()
    inspection = inspect_image(raw, "rich.jpg")
    inv = inspection.inventory
    assert inv is not None

    # Substantially more than the legacy 15 EXIF + 6 XMP + 9 IPTC fields
    assert inv.coverage.total_records >= 30
    assert "ICC Colour Profile" in inv.coverage.categories_found
    assert "EXIF MakerNotes" in inv.coverage.categories_found
    assert "Unknown / Unclassified Metadata" in inv.coverage.categories_found
    assert "Lens Information" in inv.coverage.categories_found
    assert "IPTC Metadata" in inv.coverage.categories_found
    assert "XMP Metadata" in inv.coverage.categories_found

    # Rational number preservation (1/125)
    exp = next(r for r in inv.records if r.tag_name == "ExposureTime")
    assert exp.data_type == "rational"
    assert exp.raw_value == {"numerator": 1, "denominator": 125}
    assert "1/125" in exp.interpreted_value

    # Unknown EXIF tag preserved
    unk_exif = next(r for r in inv.records if r.tag_id == "0x9999")
    assert unk_exif.is_unknown is True

    # Undecoded MakerNote blob preserved safely with UNSUPPORTED status + PARTIAL stage
    mn = next(r for r in inv.records if r.record_id == "makernotes:0x927C:MakerNote")
    assert mn.status is MetadataStatus.UNSUPPORTED
    assert mn.raw_value["byte_length"] > MAX_BINARY_HEX_BYTES
    assert len(mn.raw_value["hex_prefix"]) == MAX_BINARY_HEX_BYTES * 2
    mn_stage = next(s for s in inv.coverage.stages if s.stage_id == "makernotes")
    assert mn_stage.completion_state is StageCompletionState.PARTIAL

    # Nested XMP preserved + custom namespace flagged unknown
    subj = next(r for r in inv.records if r.source == "XMP" and r.tag_name == "subject")
    assert subj.is_hierarchical is True
    custom_xmp = next(r for r in inv.records if r.source == "XMP" and r.tag_name == "CaseRef")
    assert custom_xmp.is_unknown is True

    # IPTC Unicode + extended/unknown datasets preserved
    headline = next(r for r in inv.records if r.source == "IPTC" and r.tag_id == "2:105")
    assert headline.interpreted_value == "Headline Unicode café"
    assert any(r.source == "IPTC" and r.tag_id == "2:15" for r in inv.records)
    assert any(r.source == "IPTC" and r.tag_id == "2:250" and r.is_unknown for r in inv.records)

    # GPS separated from ordinary inventory
    assert inv.gps_present_indicator is True
    serialized = json.dumps(inv.to_dict())
    assert "37.808" not in serialized
    assert "-122.404" not in serialized

    # PT-EA/1.0.0 assessment remains completely independent
    assessment = assess_inspection(inspection)
    assert assessment.outcome is AssessmentOutcome.LOW_CONCERN


def test_extended_xmp_reports_partial_coverage_and_warning():
    buf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(buf, format="JPEG")
    std_xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:dc="http://purl.org/dc/elements/1.1/">'
        b'<rdf:Description><dc:creator>Alice</dc:creator></rdf:Description>'
        b'</rdf:RDF></x:xmpmeta>'
    )
    jpeg = _inject_jpeg_app_segments(
        buf.getvalue(),
        [
            (0xE1, XMP_JPEG_HEADER + std_xmp),
            (0xE1, XMP_JPEG_EXTENDED_HEADER + b"guid\x00\x00\x00\x00" + b"<x/>"),
        ],
    )
    inspection = inspect_image(jpeg, "ext_xmp.jpg")
    xmp_stage = next(s for s in inspection.inventory.coverage.stages if s.stage_id == "xmp")
    assert xmp_stage.completion_state is StageCompletionState.PARTIAL
    assert any(w.code == "XMP_EXTENDED_DETECTED" for w in xmp_stage.warnings)


def test_malformed_iptc_and_corrupt_icc_isolated_per_stage():
    buf = BytesIO()
    exif = Image.Exif()
    exif[271] = "Nikon"
    Image.new("RGB", (16, 16), color="white").save(
        buf, format="JPEG", exif=exif, icc_profile=b"NOT_A_VALID_ICC_PROFILE" * 4
    )
    bad_iptc = b"Photoshop 3.0\x008BIM\x04\x04\x00\x00\x00\x00\x00\x05BAD!!"
    jpeg = _inject_jpeg_app_segments(buf.getvalue(), [(0xED, bad_iptc)])

    inspection = inspect_image(jpeg, "partial_bad.jpg")
    stages = {s.stage_id: s for s in inspection.inventory.coverage.stages}
    assert stages["exif"].completion_state is StageCompletionState.COMPLETED
    assert stages["iptc"].completion_state is StageCompletionState.FAILED
    assert stages["icc"].completion_state is StageCompletionState.FAILED


def test_png_text_chunks_and_bmp_unsupported_stages():
    png_buf = BytesIO()
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Bob Müller")
    meta.add_text("Software", "GIMP 2.10")
    Image.new("RGB", (12, 12), color="black").save(png_buf, format="PNG", pnginfo=meta)
    png_insp = inspect_image(png_buf.getvalue(), "sample.png")
    assert any(r.tag_name == "Author" and r.interpreted_value == "Bob Müller" for r in png_insp.inventory.records)

    bmp_buf = BytesIO()
    Image.new("RGB", (12, 12), color="black").save(bmp_buf, format="BMP")
    bmp_insp = inspect_image(bmp_buf.getvalue(), "sample.bmp")
    assert "EXIF" in bmp_insp.inventory.coverage.unsupported_sources
    assert "File Information" in bmp_insp.inventory.coverage.categories_found


def test_xmp_node_limit_prevents_unbounded_traversal():
    buf = BytesIO()
    Image.new("RGB", (12, 12), color="white").save(buf, format="JPEG")
    items = "".join(f"<rdf:li>item-{i}</rdf:li>" for i in range(1100))
    big_xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:dc="http://purl.org/dc/elements/1.1/">'
        b'<rdf:Description><dc:subject><rdf:Bag>'
        + items.encode("ascii")
        + b"</rdf:Bag></dc:subject></rdf:Description></rdf:RDF></x:xmpmeta>"
    )
    jpeg = _inject_jpeg_app_segments(buf.getvalue(), [(0xE1, XMP_JPEG_HEADER + big_xmp)])
    inv = extract_metadata_inventory(jpeg, "JPEG", inspect_image(buf.getvalue(), "a.jpg").properties)
    xmp_stage = next(s for s in inv.coverage.stages if s.stage_id == "xmp")
    assert xmp_stage.completion_state is StageCompletionState.PARTIAL
    assert any(w.code == "XMP_NODE_LIMIT" for w in xmp_stage.warnings)


def test_whatsapp_stripped_jpeg_and_container_chunks_extracted():
    # Stripped JPEG (no EXIF, no XMP, no IPTC) still yields container, JFIF/segments, and honest limitation
    jbuf = BytesIO()
    Image.new("RGB", (32, 24), color=(10, 20, 30)).save(jbuf, format="JPEG")
    j_insp = inspect_image(jbuf.getvalue(), "WhatsApp Image 2026-11-26.jpg")
    assert any(r.tag_name == "JPEG marker segments" for r in j_insp.inventory.records)
    assert any(
        "Some metadata may have been removed or was not present" in lim
        for lim in j_insp.inventory.coverage.limitations
    )

    # PNG chunk inventory
    pbuf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(pbuf, format="PNG")
    p_insp = inspect_image(pbuf.getvalue(), "sample.png")
    assert any(r.tag_name == "PNG chunks" for r in p_insp.inventory.records)

    # WebP RIFF chunk inventory
    wbuf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(wbuf, format="WEBP")
    w_insp = inspect_image(wbuf.getvalue(), "sample.webp")
    assert any(r.tag_name == "WebP RIFF chunks" and r.source == "WebP RIFF Chunk" for r in w_insp.inventory.records)


def test_file_image_and_exif_record_mapping_accuracy():
    from PIL.TiffImagePlugin import IFDRational

    exif = Image.Exif()
    exif[271] = "Canon"
    exif[272] = "EOS 5D"
    exif[274] = 1
    exif_ifd = exif.get_ifd(0x8769)
    exif_ifd[36867] = "2026:01:02 10:20:30"
    exif_ifd[33434] = IFDRational(1, 100)
    exif_ifd[33437] = IFDRational(18, 10)
    buf = BytesIO()
    Image.new("RGB", (32, 24), color="white").save(buf, format="JPEG", exif=exif)

    insp = inspect_image(buf.getvalue(), "photo.jpg")
    by_id = {r.record_id: r for r in insp.inventory.records}

    # File Information records have accurate sources, namespaces, paths, and readable interpretations
    sig = by_id["container:file:FileSignature"]
    assert sig.source == "File Inspector"
    assert sig.namespace == "File"
    assert sig.path == ("File", "FileSignature")
    assert "JPEG SOI" in sig.interpreted_value

    fmt = by_id["container:file:DetectedFormat"]
    assert fmt.source == "Image Decoder"
    assert fmt.raw_value == "JPEG"
    assert "Joint Photographic Experts Group" in fmt.interpreted_value

    ext_mm = by_id["container:file:ExtensionMismatch"]
    assert ext_mm.source == "File Inspector"
    assert ext_mm.raw_value is False
    assert ext_mm.interpreted_value.startswith("No ")

    # EXIF records preserve tag IDs, EXIF paths, raw values, and clean interpretations
    make_rec = by_id["exif:Image:0x010F:Make"]
    assert make_rec.tag_id == "0x010F"
    assert make_rec.path == ("EXIF", "Image", "Make")

    exp_rec = by_id["exif:EXIF:0x829A:ExposureTime"]
    assert exp_rec.tag_id == "0x829A"
    assert exp_rec.interpreted_value == "1/100 s"

    fnum_rec = by_id["exif:EXIF:0x829D:FNumber"]
    assert fnum_rec.tag_id == "0x829D"
    assert fnum_rec.interpreted_value == "f/1.8"

    ori_rec = by_id["exif:Image:0x0112:Orientation"]
    assert ori_rec.tag_id == "0x0112"
    assert ori_rec.data_type == "integer"
    assert ori_rec.raw_value == 1
    assert ori_rec.interpreted_value.startswith("1 — ")


@pytest.mark.parametrize(
    "fmt,filename,with_exif",
    [
        ("JPEG", "camera.jpg", True),
        ("JPEG", "no_exif.jpg", False),
        ("JPEG", "WhatsApp Image 2026-11-26.jpg", False),
        ("PNG", "Screenshot 2026-11-26.png", False),
        ("PNG", "png_with_exif.png", True),
        ("WEBP", "photo.webp", True),
        ("TIFF", "scan.tiff", True),
        ("GIF", "anim.gif", False),
        ("BMP", "bitmap.bmp", False),
    ],
)
def test_image_information_extracted_independently_of_exif(fmt: str, filename: str, with_exif: bool):
    exif = Image.Exif()
    if with_exif:
        exif[271] = "TestMake"
    buf = BytesIO()
    mode = "RGB" if fmt in {"JPEG", "BMP", "TIFF"} else "RGBA"
    color = (40, 80, 120) if mode == "RGB" else (40, 80, 120, 255)
    save_kwargs = {}
    if with_exif and fmt in {"JPEG", "PNG", "WEBP"}:
        save_kwargs["exif"] = exif
    elif with_exif and fmt == "TIFF":
        save_kwargs["exif"] = exif.tobytes()
    if fmt in {"JPEG", "PNG"}:
        save_kwargs["dpi"] = (72, 72)
    Image.new(mode, (48, 32), color=color).save(buf, format=fmt, **save_kwargs)

    insp = inspect_image(buf.getvalue(), filename)
    by_id = {r.record_id: r for r in insp.inventory.records}
    assert by_id["container:image:Dimensions"].raw_value == "48 × 32"
    assert by_id["container:image:Width"].raw_value == 48
    assert by_id["container:image:Height"].raw_value == 32
    assert by_id["container:image:ColorMode"].raw_value == insp.properties.color_mode
    assert by_id["container:image:ColourChannels"].raw_value >= 1
    assert by_id["container:image:FrameCount"].raw_value == 1
    if fmt in {"JPEG", "PNG"}:
        dpi_interp = by_id["container:info:dpi"].interpreted_value
        assert "72" in dpi_interp and "DPI" in dpi_interp


def test_jpeg_jfif_sof_subsampling_progressive_and_whatsapp_1200x1600():
    # 1. 1200x1600 progressive JPEG (4:2:0) without EXIF, JFIF 1.01, unit=0
    buf = BytesIO()
    Image.new("RGB", (1200, 1600), color=(30, 60, 90)).save(
        buf, format="JPEG", progressive=True, subsampling=2
    )
    insp = inspect_image(buf.getvalue(), "WhatsApp Image.jpg")
    by_id = {r.record_id: r for r in insp.inventory.records}

    assert by_id["container:file:FileExtension"].raw_value == "jpg"
    assert by_id["container:file:RawHeaderPreview"].raw_value.startswith("FF D8 FF E0")
    assert by_id["container:image:Megapixels"].interpreted_value.startswith("1.92 MP")
    assert by_id["container:jpeg:jfif:JFIFVersion"].raw_value == "1.01"
    assert by_id["container:jpeg:jfif:ResolutionUnit"].raw_value == 0
    assert "DPI" not in by_id["container:jpeg:jfif:XResolution"].interpreted_value
    assert by_id["container:jpeg:sof:EncodingProcess"].interpreted_value == "Progressive DCT, Huffman coding"
    assert by_id["container:jpeg:sof:Progressive"].raw_value is True
    assert by_id["container:jpeg:sof:Precision"].raw_value == 8
    assert by_id["container:jpeg:sof:ColorComponents"].raw_value == 3
    assert by_id["container:jpeg:sof:ComponentSampling"].interpreted_value == "YCbCr 4:2:0 (2 2)"

    # 2. Baseline 4:2:2 and 4:4:4 + density unit 1
    for subs, expected_label in ((1, "YCbCr 4:2:2 (2 1)"), (0, "YCbCr 4:4:4 (1 1)")):
        b = BytesIO()
        Image.new("RGB", (32, 32), color="white").save(
            b, format="JPEG", progressive=False, subsampling=subs, dpi=(96, 96)
        )
        r_map = {r.record_id: r for r in inspect_image(b.getvalue(), "base.jpg").inventory.records}
        assert r_map["container:jpeg:jfif:ResolutionUnit"].raw_value == 1
        assert "96 DPI" in r_map["container:jpeg:jfif:XResolution"].interpreted_value
        assert r_map["container:jpeg:sof:EncodingProcess"].interpreted_value == "Baseline DCT, Huffman coding"
        assert r_map["container:jpeg:sof:Progressive"].raw_value is False
        assert r_map["container:jpeg:sof:ComponentSampling"].interpreted_value == expected_label


def test_jpeg_malformed_app0_sof_and_truncated_segments_handled_safely():
    base_buf = BytesIO()
    Image.new("RGB", (16, 16), color="white").save(base_buf, format="JPEG")
    props = inspect_image(base_buf.getvalue(), "base.jpg").properties

    # Malformed APP0 (truncated JFIF payload)
    bad_app0 = b"\xff\xd8\xff\xe0\x00\x09JFIF\x00\x01\x01\xff\xd9"
    inv1 = extract_metadata_inventory(bad_app0, "JPEG", props)
    assert any(w.code == "JPEG_APP0_MALFORMED" for w in inv1.coverage.warnings)

    # Malformed SOF (truncated SOF0 payload)
    bad_sof = b"\xff\xd8\xff\xc0\x00\x04\x08\x00\xff\xd9"
    inv2 = extract_metadata_inventory(bad_sof, "JPEG", props)
    assert any(w.code == "JPEG_SOF_MALFORMED" for w in inv2.coverage.warnings)

    # Invalid segment length (seg_len=1 < 2)
    bad_len = b"\xff\xd8\xff\xe1\x00\x01\xff\xd9"
    inv3 = extract_metadata_inventory(bad_len, "JPEG", props)
    assert any(w.code == "JPEG_SEGMENT_INVALID" for w in inv3.coverage.warnings)

    # Truncated JPEG
    trunc = b"\xff\xd8\xff\xe0\x00"
    inv4 = extract_metadata_inventory(trunc, "JPEG", props)
    assert any(w.code == "JPEG_TRUNCATED" for w in inv4.coverage.warnings)
