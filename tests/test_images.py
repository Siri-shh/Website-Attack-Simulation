"""Upload validation at the decoded-image boundary."""

from io import BytesIO

from PIL import Image
import pytest


def raster(fmt, *, size=(8, 8)):
    output = BytesIO()
    Image.new("RGB", size, (31, 97, 173)).save(output, format=fmt)
    return output.getvalue()


@pytest.mark.parametrize(("format_name", "mime"), [
    ("PNG", "image/png"), ("JPEG", "image/jpeg"),
])
def test_accepts_complete_png_and_jpeg_without_changing_bytes(format_name, mime):
    from security_lab.images import validate_image_upload

    raw = raster(format_name)
    assert validate_image_upload(raw, mime) == (raw, mime)


@pytest.mark.parametrize(("raw", "mime"), [
    (b"not an image", "image/png"),
    (b"", "image/png"),
    (raster("PNG"), "image/jpeg"),
    (raster("JPEG"), "image/png"),
    (raster("PNG"), "application/octet-stream"),
    (raster("PNG")[:len(raster("PNG")) // 2], "image/png"),
    (raster("JPEG")[:len(raster("JPEG")) // 2], "image/jpeg"),
])
def test_rejects_invalid_spoofed_or_truncated_uploads(raw, mime):
    from security_lab.images import validate_image_upload

    with pytest.raises(ValueError):
        validate_image_upload(raw, mime)


def test_rejects_more_than_one_mebibyte_even_for_valid_image_prefix():
    from security_lab.images import validate_image_upload

    raw = raster("PNG") + b"padding" * 150_000
    assert len(raw) > 1_048_576
    with pytest.raises(ValueError):
        validate_image_upload(raw, "image/png")


def test_rejects_more_than_sixteen_million_decoded_pixels():
    from security_lab.images import validate_image_upload

    raw = raster("PNG", size=(4001, 4000))
    assert len(raw) <= 1_048_576
    with pytest.raises(ValueError):
        validate_image_upload(raw, "image/png")


def test_decompression_bomb_warning_is_a_validation_error(monkeypatch):
    from security_lab.images import validate_image_upload

    raw = raster("PNG", size=(64, 64))
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 1_024)
    with pytest.raises(ValueError):
        validate_image_upload(raw, "image/png")
