"""Bounded PNG/JPEG upload validation before image evidence is saved."""

from io import BytesIO
import warnings

from PIL import Image


MAX_IMAGE_BYTES = 1_048_576
MAX_IMAGE_PIXELS = 16_000_000
_MIME_FOR_FORMAT = {"PNG": "image/png", "JPEG": "image/jpeg"}


def validate_image_upload(raw: bytes, declared_mime: str) -> tuple[bytes, str]:
    """Return complete original raster bytes and their verified canonical MIME."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_IMAGE_BYTES:
        raise ValueError("Image must contain at most 1 MiB of bytes")
    if type(declared_mime) is not str or declared_mime not in _MIME_FOR_FORMAT.values():
        raise ValueError("Only PNG and JPEG images are accepted")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(raw), formats=("PNG", "JPEG")) as image:
                mime = _MIME_FOR_FORMAT[image.format]
                width, height = image.size
                if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                    raise ValueError("Image dimensions exceed the allowed size")
                image.verify()
            # verify() consumes the parser state; decoding a fresh handle
            # catches damaged pixel streams that header checks can miss.
            with Image.open(BytesIO(raw), formats=("PNG", "JPEG")) as image:
                if _MIME_FOR_FORMAT[image.format] != mime or image.size != (width, height):
                    raise ValueError("Image changed during validation")
                image.load()
    except Exception as exc:
        raise ValueError("Invalid PNG or JPEG image") from exc
    if declared_mime != mime:
        raise ValueError("Declared image type does not match decoded content")
    return raw, mime
