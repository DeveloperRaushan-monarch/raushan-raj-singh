from fractions import Fraction
from io import BytesIO

import pytest
from PIL import Image

from core.analysis import inspect_image
from core.gps import extract_gps
from core.models import MetadataStatus


def make_image_with_gps(image_format="JPEG"):
    exif = Image.Exif()
    exif[34853] = {
        1: "N",
        2: (Fraction(37), Fraction(48), Fraction(30)),
        3: "W",
        4: (Fraction(122), Fraction(24), Fraction(15)),
        6: Fraction(12),
        7: (Fraction(10), Fraction(20), Fraction(30)),
        29: "2024:01:02",
    }
    output = BytesIO()
    exif_value = exif.tobytes() if image_format == "TIFF" else exif
    Image.new("RGB", (8, 8), "white").save(output, format=image_format, exif=exif_value)
    return output.getvalue()


@pytest.mark.parametrize("image_format", ["JPEG", "PNG", "WEBP", "TIFF"])
def test_gps_is_extracted_only_through_explicit_gps_function(image_format):
    result = extract_gps(make_image_with_gps(image_format), image_format)
    assert result.status is MetadataStatus.PRESENT
    assert abs(result.latitude - 37.8083333333) < 1e-8
    assert abs(result.longitude - (-122.4041666667)) < 1e-8
    assert result.altitude_meters == 12
    assert result.timestamp_utc == "2024-01-02 10:20:30 UTC"


def test_absent_gps_returns_missing_without_coordinates():
    output = BytesIO()
    Image.new("RGB", (8, 8), "white").save(output, format="JPEG")
    result = extract_gps(output.getvalue())
    assert result.status is MetadataStatus.MISSING
    assert result.latitude is None
    assert result.longitude is None


def test_regular_inspection_does_not_expose_gps_fields():
    file_bytes = make_image_with_gps()
    result = inspect_image(file_bytes, "location.jpg")
    assert not any("gps" in field.key.lower() for field in result.metadata)
    assert not any("37.8" in finding.observed_evidence for finding in result.findings)


@pytest.mark.parametrize(
    "lat_ref,lat_dms,lon_ref,lon_dms,expected_lat,expected_lon",
    [
        ("N", (Fraction(12), Fraction(30), Fraction(0)), "E", (Fraction(77), Fraction(30), Fraction(0)), 12.5, 77.5),
        ("S", (Fraction(33), Fraction(51), Fraction(0)), "W", (Fraction(70), Fraction(40), Fraction(0)), -33.85, -70.6666666667),
        ("N", (Fraction(0), Fraction(0), Fraction(0)), "E", (Fraction(0), Fraction(0), Fraction(0)), 0.0, 0.0),
        ("N", (Fraction(0), Fraction(0), Fraction(0)), "W", (Fraction(45), Fraction(0), Fraction(0)), 0.0, -45.0),
    ],
)
def test_gps_hemispheres_and_valid_zero_coordinates(lat_ref, lat_dms, lon_ref, lon_dms, expected_lat, expected_lon):
    exif = Image.Exif()
    exif[34853] = {
        0: b"\x02\x03\x00\x00",
        1: lat_ref,
        2: lat_dms,
        3: lon_ref,
        4: lon_dms,
        18: "WGS-84",
        27: b"ASCII\x00\x00\x00GPS",
    }
    buf = BytesIO()
    Image.new("RGB", (8, 8), "white").save(buf, format="JPEG", exif=exif)
    res = extract_gps(buf.getvalue(), "JPEG")
    assert res.status is MetadataStatus.PRESENT
    assert res.gps_state == "GPS_COORDINATES_AVAILABLE"
    assert abs(res.latitude - expected_lat) < 1e-6
    assert abs(res.longitude - expected_lon) < 1e-6
    raw_dict = dict(res.raw_tags)
    extra_dict = dict(res.extra_properties)
    assert "GPSLatitude" in raw_dict
    assert extra_dict.get("GPSMapDatum") == "WGS-84"
    assert extra_dict.get("GPSProcessingMethod") == "GPS"


@pytest.mark.parametrize(
    "gps_ifd,expected_state",
    [
        ({1: "N", 2: (Fraction(37), Fraction(0), Fraction(0))}, "GPS_COORDINATES_INCOMPLETE"),
        ({2: (Fraction(37), Fraction(0), Fraction(0)), 3: "E", 4: (Fraction(10), Fraction(0), Fraction(0))}, "GPS_COORDINATES_INCOMPLETE"),
        ({1: "N", 2: (Fraction(91), Fraction(0), Fraction(0)), 3: "E", 4: (Fraction(10), Fraction(0), Fraction(0))}, "GPS_COORDINATES_INVALID"),
        ({1: "N", 2: (Fraction(10), Fraction(0), Fraction(0)), 3: "E", 4: (Fraction(181), Fraction(0), Fraction(0))}, "GPS_COORDINATES_INVALID"),
        ({1: "N", 2: (Fraction(10), Fraction(60), Fraction(0)), 3: "E", 4: (Fraction(10), Fraction(0), Fraction(0))}, "GPS_COORDINATES_INVALID"),
    ],
)
def test_gps_incomplete_and_invalid_coordinates_rejected(gps_ifd, expected_state):
    exif = Image.Exif()
    exif[34853] = gps_ifd
    buf = BytesIO()
    Image.new("RGB", (8, 8), "white").save(buf, format="JPEG", exif=exif)
    res = extract_gps(buf.getvalue(), "JPEG")
    assert res.status is MetadataStatus.INVALID
    assert res.gps_state == expected_state
    assert res.latitude is None
    assert res.longitude is None


def test_gps_zero_denominator_and_coordinate_unit_rejects():
    from core.gps import _coordinate

    class BadRational:
        num = 10
        den = 0

    assert _coordinate((BadRational(), Fraction(0), Fraction(0)), "N", latitude=True) is None
    assert _coordinate((Fraction(-10), Fraction(0), Fraction(0)), "N", latitude=True) is None
    assert _coordinate((Fraction(0), Fraction(0), Fraction(0)), b"N", latitude=True) == 0.0


def test_extract_gps_xmp_fallback():
    xmp_packet = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:exif="http://ns.adobe.com/exif/1.0/" '
        b'exif:GPSLatitude="37,48.5N" exif:GPSLongitude="122,24.25W" '
        b'exif:GPSAltitude="100/2" exif:GPSAltitudeRef="0"/>'
        b'</rdf:RDF></x:xmpmeta>'
    )
    buf = BytesIO()
    Image.new("RGB", (16, 16), color=(10, 20, 30)).save(buf, format="JPEG")
    raw = buf.getvalue()
    # Inject XMP APP1 segment right after SOI (FF D8)
    payload = b"http://ns.adobe.com/xap/1.0/\x00" + xmp_packet
    app1 = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    jpeg_with_xmp = raw[:2] + app1 + raw[2:]

    res = extract_gps(jpeg_with_xmp, "JPEG")
    assert res.status is MetadataStatus.PRESENT
    assert res.gps_state == "GPS_COORDINATES_AVAILABLE"
    assert res.latitude == pytest.approx(37.0 + 48.5 / 60.0)
    assert res.longitude == pytest.approx(-(122.0 + 24.25 / 60.0))
    assert res.altitude_meters == pytest.approx(50.0)
