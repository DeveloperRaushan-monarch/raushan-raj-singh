from io import BytesIO

from PIL import Image, PngImagePlugin, TiffImagePlugin
import pytest

from core.metadata import extract_metadata
from core.models import MetadataStatus
from core.xmp import XMP_JPEG_EXTENDED_HEADER, XMP_JPEG_HEADER


XMP_XML = b'''<?xpacket begin=""?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
 <rdf:RDF><rdf:Description xmp:CreateDate="2024-05-06T07:08:09Z" xmp:ModifyDate="2024-05-07T08:09:10Z"
 xmp:CreatorTool="PIXELTRUTH fixture">
  <dc:creator><rdf:Seq><rdf:li>Ada Example</rdf:li><rdf:li>Lin Example</rdf:li></rdf:Seq></dc:creator>
  <dc:description><rdf:Alt><rdf:li xml:lang="x-default">Synthetic description</rdf:li></rdf:Alt></dc:description>
  <dc:rights><rdf:Alt><rdf:li>Example rights</rdf:li></rdf:Alt></dc:rights>
 </rdf:Description></rdf:RDF>
</x:xmpmeta><?xpacket end="w"?>'''


def make_jpeg() -> bytes:
    output = BytesIO()
    Image.new("RGB", (8, 6), "white").save(output, format="JPEG")
    return output.getvalue()


def jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + (len(payload) + 2).to_bytes(2, "big") + payload


def add_jpeg_segments(image_bytes: bytes, *segments: bytes) -> bytes:
    return image_bytes[:2] + b"".join(segments) + image_bytes[2:]


def iim_dataset(record: int, dataset: int, value: bytes) -> bytes:
    return b"\x1c" + bytes((record, dataset)) + len(value).to_bytes(2, "big") + value


def photoshop_resource(resource_id: int, data: bytes) -> bytes:
    name = b"\x00\x00"  # Empty Pascal name plus even-byte padding.
    block = b"8BIM" + resource_id.to_bytes(2, "big") + name + len(data).to_bytes(4, "big") + data
    if len(data) & 1:
        block += b"\x00"
    return block


def fields_by_key(file_bytes: bytes, image_format: str):
    return {field.key: field for field in extract_metadata(file_bytes, image_format)}


def test_jpeg_extracts_xmp_creator_dates_description_software_and_rights():
    data = add_jpeg_segments(make_jpeg(), jpeg_segment(0xE1, XMP_JPEG_HEADER + XMP_XML))
    fields = fields_by_key(data, "JPEG")
    assert fields["xmp"].status is MetadataStatus.PRESENT
    assert fields["xmp_creator"].value == "Ada Example; Lin Example"
    assert fields["xmp_creation_date"].value == "2024-05-06T07:08:09Z"
    assert fields["xmp_modification_date"].value == "2024-05-07T08:09:10Z"
    assert fields["xmp_description"].value == "Synthetic description"
    assert fields["xmp_software"].value == "PIXELTRUTH fixture"
    assert fields["xmp_rights"].value == "Example rights"
    assert fields["xmp_creator"].source == "XMP"


def test_png_and_webp_xmp_storage_locations_are_read():
    png_info = PngImagePlugin.PngInfo()
    png_info.add_itxt("XML:com.adobe.xmp", XMP_XML.decode("utf-8"))
    png_bytes = BytesIO()
    Image.new("RGB", (8, 6), "white").save(png_bytes, format="PNG", pnginfo=png_info)
    assert fields_by_key(png_bytes.getvalue(), "PNG")["xmp_software"].value == "PIXELTRUTH fixture"

    webp_bytes = BytesIO()
    Image.new("RGB", (8, 6), "white").save(webp_bytes, format="WEBP", xmp=XMP_XML)
    assert fields_by_key(webp_bytes.getvalue(), "WEBP")["xmp_creator"].value == "Ada Example; Lin Example"


def test_tiff_xmp_tag_700_is_read():
    ifd = TiffImagePlugin.ImageFileDirectory_v2()
    ifd[700] = XMP_XML + b"\x00"
    output = BytesIO()
    Image.new("RGB", (8, 6), "white").save(output, format="TIFF", tiffinfo=ifd)
    assert fields_by_key(output.getvalue(), "TIFF")["xmp_rights"].value == "Example rights"


def test_malformed_xmp_is_invalid_and_does_not_crash():
    data = add_jpeg_segments(make_jpeg(), jpeg_segment(0xE1, XMP_JPEG_HEADER + b"<x:xmpmeta><bad>"))
    fields = fields_by_key(data, "JPEG")
    assert fields["xmp"].status is MetadataStatus.INVALID
    assert fields["xmp_creator"].status is MetadataStatus.UNAVAILABLE


def test_xmp_external_entity_declarations_are_rejected():
    packet = b'<!DOCTYPE x [<!ENTITY data SYSTEM "file:///etc/passwd">]><x:xmpmeta>&data;</x:xmpmeta>'
    data = add_jpeg_segments(make_jpeg(), jpeg_segment(0xE1, XMP_JPEG_HEADER + packet))
    assert fields_by_key(data, "JPEG")["xmp"].status is MetadataStatus.INVALID


def test_jpeg_extended_xmp_is_explicitly_unsupported():
    data = add_jpeg_segments(
        make_jpeg(), jpeg_segment(0xE1, XMP_JPEG_EXTENDED_HEADER + b"opaque extended packet")
    )
    fields = fields_by_key(data, "JPEG")
    assert fields["xmp"].status is MetadataStatus.UNSUPPORTED
    assert "not reassembled" in fields["xmp"].note


def test_absent_xmp_and_iptc_are_missing_and_bmp_is_unsupported():
    fields = fields_by_key(make_jpeg(), "JPEG")
    assert fields["xmp"].status is MetadataStatus.MISSING
    assert fields["iptc"].status is MetadataStatus.MISSING
    bmp = BytesIO()
    Image.new("RGB", (4, 4), "white").save(bmp, format="BMP")
    unsupported = fields_by_key(bmp.getvalue(), "BMP")
    assert unsupported["xmp"].status is MetadataStatus.UNSUPPORTED
    assert unsupported["iptc"].status is MetadataStatus.UNSUPPORTED


def test_jpeg_extracts_iptc_headline_caption_keywords_byline_and_location():
    iim = b"".join(
        (
            iim_dataset(2, 105, b"Test headline"),
            iim_dataset(2, 120, b"Synthetic caption"),
            iim_dataset(2, 25, b"first keyword"),
            iim_dataset(2, 25, b"second keyword"),
            iim_dataset(2, 25, b"first keyword"),
            iim_dataset(2, 80, b"Example creator"),
            iim_dataset(2, 116, b"Example copyright"),
            iim_dataset(2, 55, b"20241026"),
            iim_dataset(2, 90, b"Example city"),
            iim_dataset(2, 92, b"Example district"),
            iim_dataset(2, 101, b"Example country"),
        )
    )
    app13 = jpeg_segment(0xED, b"Photoshop 3.0\x00" + photoshop_resource(0x0404, iim))
    data = add_jpeg_segments(make_jpeg(), app13)
    fields = fields_by_key(data, "JPEG")
    assert fields["iptc"].status is MetadataStatus.PRESENT
    assert fields["iptc_headline"].value == "Test headline"
    assert fields["iptc_caption"].value == "Synthetic caption"
    assert fields["iptc_keywords"].value == "first keyword; second keyword; first keyword"
    assert fields["iptc_creator"].value == "Example creator"
    assert fields["iptc_copyright"].value == "Example copyright"
    assert fields["iptc_date_created"].value == "20241026"
    assert fields["iptc_city"].value == "Example city"
    assert fields["iptc_sublocation"].value == "Example district"
    assert fields["iptc_country"].value == "Example country"
    assert fields["iptc_keywords"].source == "IPTC"


def test_tiff_iptc_tag_33723_is_read():
    iim = iim_dataset(2, 105, b"TIFF headline")
    ifd = TiffImagePlugin.ImageFileDirectory_v2()
    ifd[33723] = iim
    output = BytesIO()
    Image.new("RGB", (8, 6), "white").save(output, format="TIFF", tiffinfo=ifd)
    fields = fields_by_key(output.getvalue(), "TIFF")
    assert fields["iptc_headline"].value == "TIFF headline"


def test_truncated_iptc_length_is_invalid():
    truncated = b"\x1c\x02\x69\x00\x08short"
    app13 = jpeg_segment(0xED, b"Photoshop 3.0\x00" + photoshop_resource(0x0404, truncated))
    fields = fields_by_key(add_jpeg_segments(make_jpeg(), app13), "JPEG")
    assert fields["iptc"].status is MetadataStatus.INVALID


def test_jpeg_can_contain_xmp_and_iptc_and_existing_exif():
    exif = Image.Exif()
    exif[271] = "Example Camera"
    base = BytesIO()
    Image.new("RGB", (8, 6), "white").save(base, format="JPEG", exif=exif)
    iim = iim_dataset(2, 105, b"Combined fixture")
    data = add_jpeg_segments(
        base.getvalue(),
        jpeg_segment(0xE1, XMP_JPEG_HEADER + XMP_XML),
        jpeg_segment(0xED, b"Photoshop 3.0\x00" + photoshop_resource(0x0404, iim)),
    )
    fields = fields_by_key(data, "JPEG")
    assert fields["make"].value == "Example Camera"
    assert fields["xmp_software"].status is MetadataStatus.PRESENT
    assert fields["iptc_headline"].value == "Combined fixture"


@pytest.mark.parametrize("image_format", ["BMP", "GIF"])
def test_iptc_unsupported_formats_are_not_reported_as_missing(image_format):
    output = BytesIO()
    Image.new("RGB", (4, 4), "white").save(output, format=image_format)
    assert fields_by_key(output.getvalue(), image_format)["iptc"].status is MetadataStatus.UNSUPPORTED
