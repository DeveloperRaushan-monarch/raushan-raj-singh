"""Bounded, descriptive RGB intensity histograms for validated images."""

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, UnidentifiedImageError

from utils.validators import ImageValidationError, ValidatedImage, validate_image_bytes


HISTOGRAM_BINS = 256
_CHUNK_PIXEL_BUDGET = 1_000_000


class HistogramError(ValueError):
    """A histogram request could not be completed safely."""


@dataclass(frozen=True)
class HistogramResult:
    width: int
    height: int
    frame_count: int
    frame_dimensions: tuple[tuple[int, int], ...]
    pixel_count: int
    red: tuple[int, ...]
    green: tuple[int, ...]
    blue: tuple[int, ...]
    combined: tuple[int, ...]
    method: str
    limitations: str


def calculate_rgb_histogram(file_bytes: bytes, filename: str = "histogram-input") -> HistogramResult:
    """Return RGB intensity counts across every frame of a validated image.

    Pixel data is processed in bounded tiles to limit temporary RGB
    allocations. Alpha transparency and embedded color profiles are not
    applied to or used to adjust the channel values.
    """
    try:
        validated = validate_image_bytes(file_bytes, filename)
    except ImageValidationError as exc:
        raise HistogramError(str(exc)) from exc

    red_counts = [0] * HISTOGRAM_BINS
    green_counts = [0] * HISTOGRAM_BINS
    blue_counts = [0] * HISTOGRAM_BINS

    try:
        with Image.open(BytesIO(file_bytes)) as image:
            for frame_index, (frame_width, frame_height) in enumerate(validated.frame_dimensions):
                image.seek(frame_index)
                if image.size != (frame_width, frame_height):
                    raise HistogramError("Image frame dimensions changed during histogram analysis.")
                tile_width = min(frame_width, _CHUNK_PIXEL_BUDGET)
                rows_per_chunk = max(1, _CHUNK_PIXEL_BUDGET // tile_width)
                for left in range(0, frame_width, tile_width):
                    right = min(left + tile_width, frame_width)
                    for top in range(0, frame_height, rows_per_chunk):
                        bottom = min(top + rows_per_chunk, frame_height)
                        rgb_chunk = image.crop((left, top, right, bottom)).convert("RGB")
                        red, green, blue = rgb_chunk.split()
                        for target, channel in zip((red_counts, green_counts, blue_counts), (red, green, blue)):
                            for value, count in enumerate(channel.histogram()):
                                target[value] += count
    except HistogramError:
        raise
    except (OSError, EOFError, SyntaxError, ValueError, UnidentifiedImageError) as exc:
        raise HistogramError("The image could not be decoded for histogram analysis.") from exc

    combined_counts = tuple(
        red_counts[value] + green_counts[value] + blue_counts[value]
        for value in range(HISTOGRAM_BINS)
    )
    pixel_count = sum(width * height for width, height in validated.frame_dimensions)
    return HistogramResult(
        width=validated.width,
        height=validated.height,
        frame_count=validated.frame_count,
        frame_dimensions=validated.frame_dimensions,
        pixel_count=pixel_count,
        red=tuple(red_counts),
        green=tuple(green_counts),
        blue=tuple(blue_counts),
        combined=combined_counts,
        method=(
            "Pillow decoded every frame as RGB; all frames are pooled into the channel counts. "
            "Counts are computed in bounded image tiles."
        ),
        limitations=(
            "Transparency is discarded during RGB conversion and embedded color profiles are not applied. "
            "For multi-frame images, the histogram pools all frames and does not show changes over time. "
            "Histograms describe pixel intensities and are not authenticity tests or proof of manipulation."
        ),
    )

