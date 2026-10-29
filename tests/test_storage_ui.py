"""Owner-only evidence and saved-operation timing presentation tests."""

import base64
from contextlib import closing
from io import BytesIO
from pathlib import Path
import random
import re

import pytest
from jinja2 import FileSystemLoader
from PIL import Image

from security_lab import records
from security_lab.audit import verify_app_event
from security_lab.config import format_ist
from security_lab.crypto import open_record_image, open_record_measured
from security_lab.db import connect, transaction


_TEMPLATE_ROOT = Path(__file__).parents[1] / "security_lab" / "templates"


@pytest.fixture
def real_storage_client(storage_app):
    """Exercise packaged templates, bypassing conftest's route-contract stubs."""
    storage_app.jinja_loader = FileSystemLoader(str(_TEMPLATE_ROOT))
    storage_app.jinja_env.cache.clear()
    return storage_app.test_client()


def _csrf(client, path="/login"):
    response = client.get(path, base_url="https://localhost")
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.data.decode("utf-8")
    return match.group(1).decode("ascii")


def _login(client, username="alice", password="AlicePass!2026"):
    token = _csrf(client)
    response = client.post(
        "/login",
        base_url="https://localhost",
        data={"csrf_token": token, "username": username, "password": password},
        follow_redirects=False,
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 303
    return response


def _saved(config, keys, *, owner="alice", title="Evidence title", body="Evidence body",
           image_bytes=None, image_mime=None):
    image_options = {}
    if image_bytes is not None:
        image_options = {
            "image_action": "replace", "image_bytes": image_bytes, "image_mime": image_mime,
        }
    return records.save_record(
        config,
        keys,
        owner=owner,
        record_id=None,
        title=title,
        body=body,
        src_ip="192.0.2.10",
        session_ref="test-session",
        **image_options,
    )


def _image(image_format="PNG", *, large=False):
    buffer = BytesIO()
    if large:
        pixels = random.Random(7).randbytes(256 * 256 * 3)
        image = Image.frombytes("RGB", (256, 256), pixels)
    else:
        image = Image.new("RGB", (2, 2), (12, 34, 56))
    image.save(buffer, format=image_format)
    return buffer.getvalue()


def _rows(config, table):
    with closing(connect(config)) as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def _image_post(client, path, *, image_action, content=None, mime="image/png"):
    data = {
        "csrf_token": _csrf(client, "/records/new"),
        "title": "Image title", "body": "Image body", "image_action": image_action,
    }
    if content is not None:
        data["image"] = (BytesIO(content), "upload.png", mime)
    return client.post(
        path, base_url="https://localhost", data=data, content_type="multipart/form-data",
        follow_redirects=False,
    )


def _assert_private_image_headers(response):
    assert "no-store" in response.headers["Cache-Control"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_detail_renders_exact_saved_crypto_evidence_and_ist_times(real_storage_client, config, keys):
    _login(real_storage_client)
    row = _saved(config, keys)

    response = real_storage_client.get(f"/records/{row['id']}", base_url="https://localhost")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for value in (
        row["ciphertext_b64"],
        row["nonce_b64"],
        row["sha256_hex"],
        row["signature_b64"],
        str(row["version"]),
        format_ist(row["created_at_us"]),
        format_ist(row["updated_at_us"]),
        format_ist(row["generated_at_us"]),
        str(row["plaintext_bytes"]),
        str(row["ciphertext_bytes"]),
        str(row["envelope_bytes"]),
    ):
        assert value in html
    assert "SHA-256 hash" in html
    assert "Ed25519 digital signature" in html
    assert "Digital signature verification passed" in html
    assert "Envelope hash verification passed" in html
    assert "(IST)" in html
    assert "Updated (IST)" in html


def test_detail_escapes_script_title_and_uses_saved_timings_without_regeneration(
    real_storage_client, config, keys, monkeypatch,
):
    _login(real_storage_client)
    landing = real_storage_client.get("/", base_url="https://localhost")
    assert landing.status_code == 200
    assert b"Login successful" in landing.data
    original = records.seal_record

    def seal_with_fixed_timings(*args, **kwargs):
        row = original(*args, **kwargs)
        row.update(encryption_ns=60, hashing_ns=20, signing_ns=50)
        return row

    monkeypatch.setattr(records, "seal_record", seal_with_fixed_timings)
    saved = _saved(config, keys, title="<script>alert('x')</script>")

    def no_regeneration(*args, **kwargs):
        raise AssertionError("detail GET must not regenerate record cryptography")

    monkeypatch.setattr(records, "seal_record", no_regeneration)
    before_reads = {table: _rows(config, table) for table in ("records", "record_versions")}
    paths = [f"/records/{saved['id']}"] * 2
    responses = [real_storage_client.get(path, base_url="https://localhost") for path in paths]
    after_reads = {table: _rows(config, table) for table in ("records", "record_versions")}

    assert all(response.status_code == 200 for response in responses)
    html = [response.get_data(as_text=True) for response in responses]
    assert all("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;" in page for page in html)
    assert all("<script>alert('x')</script>" not in page for page in html)
    assert all("0.000060" in page for page in html)
    assert all("0.000020" in page for page in html)
    assert all("0.000050" in page for page in html)
    assert all(saved["nonce_b64"] in page and saved["signature_b64"] in page for page in html)
    assert all("Measured operation durations for this saved version" in page for page in html)
    assert after_reads == before_reads


def test_detail_passes_transient_current_read_timings_without_changing_saved_evidence(
    real_storage_client, config, keys, monkeypatch,
):
    from security_lab import storage

    _login(real_storage_client)
    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    before = {table: _rows(config, table) for table in ("records", "record_versions")}
    measured = {
        "hash_verification_ns": 11_000,
        "signature_verification_ns": 22_000,
        "text_decryption_ns": 33_000,
        "image_decryption_ns": 44_000,
    }
    measured_versions = []

    def fixed_measurements(keyring, row):
        measured_versions.append(row["version"])
        text, image, _ = open_record_measured(keyring, row)
        assert image == _image()
        return text, image, measured

    monkeypatch.setattr(storage, "open_record_measured", fixed_measurements, raising=False)
    original_render = storage.render_template
    contexts = []

    def capture_render(template, **context):
        if template == "storage/detail.html":
            contexts.append(context)
        return original_render(template, **context)

    monkeypatch.setattr(storage, "render_template", capture_render)
    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")

    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
    assert measured_versions == [saved["version"]]
    assert contexts[-1]["read_timings"] == measured
    assert contexts[-1]["record"] == saved
    assert contexts[-1]["plaintext"] == {"title": "Evidence title", "body": "Evidence body"}
    for table, rows in before.items():
        assert _rows(config, table) == rows


def test_detail_graph_uses_saved_sizes_and_durations_and_labels_one_point(
    real_storage_client, config, keys, monkeypatch,
):
    _login(real_storage_client)
    original = records.seal_record

    def seal_with_fixed_timings(*args, **kwargs):
        row = original(*args, **kwargs)
        row.update(encryption_ns=1200, hashing_ns=3400, signing_ns=5600,
                   image_encrypt_ns=7800, image_hash_ns=9000)
        return row

    monkeypatch.setattr(records, "seal_record", seal_with_fixed_timings)
    saved = _saved(config, keys, body="saved plaintext sample", image_bytes=_image(), image_mime="image/png")
    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Saved version measurements" in html
    assert "bytes" in html and "ns" in html
    assert "Input size labels each row; horizontal bar length encodes duration in ns" in html
    assert "Durations in ns are exact; ms values are rounded to six decimal places." in html
    assert "throughput values are rounded to six decimal places" in html.lower()
    assert "one saved version" in html.lower()
    assert "not a trend" in html.lower()
    for value in (str(saved["plaintext_bytes"]), str(saved["ciphertext_bytes"]),
                  str(saved["envelope_bytes"]), "1200", "3400", "5600"):
        assert value in html
    assert str(saved["image_size"]) in html
    assert str(saved["image_encrypt_ns"]) in html
    assert str(saved["image_hash_ns"]) in html
    image_hash_bytes = 2 * saved["image_size"] + 16
    image_hash_mib_per_s = image_hash_bytes * 1_000_000_000 / (saved["image_hash_ns"] * 1_048_576)
    assert "2 × image bytes + 16 bytes hashed" in html
    assert str(image_hash_bytes) in html
    assert f"{image_hash_mib_per_s:.6f}" in html
    assert "image aes-gcm encryption" in html.lower()
    assert "SHA-256" in html and "Ed25519" in html


def test_detail_labels_current_read_measurements_as_transient(
    real_storage_client, config, keys, monkeypatch,
):
    from security_lab import storage

    _login(real_storage_client)
    saved = _saved(config, keys)
    measured = {
        "hash_verification_ns": 101,
        "signature_verification_ns": 202,
        "text_decryption_ns": 303,
        "image_decryption_ns": None,
    }
    monkeypatch.setattr(storage, "open_record_measured", lambda keyring, row: (
        {"title": "Evidence title", "body": "Evidence body"}, None, measured
    ), raising=False)
    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Current read measurements · transient" in html
    assert "not saved" in html.lower()
    for label, value in (("Hash verification", "101"), ("Signature verification", "202"),
                         ("Text decryption", "303")):
        assert label in html and value in html
    assert "Image decryption" in html and "Not applicable" in html


def test_storage_chart_rules_have_dark_mode_contrast():
    css = (_TEMPLATE_ROOT.parent / "static" / "storage.css").read_text(encoding="utf-8")
    dark_start = css.rfind("@media (prefers-color-scheme: dark)")
    assert dark_start >= 0
    dark_rules = css[dark_start:]
    assert ".transient-read-measurements" in dark_rules and "background:" in dark_rules
    assert ".chart-data-table thead th" in dark_rules and "background:" in dark_rules


def test_detail_version_series_uses_each_saved_row_measurement(
    real_storage_client, config, keys, monkeypatch,
):
    _login(real_storage_client)
    original = records.seal_record
    elapsed = iter(((1100, 2100, 3100), (4100, 5100, 6100)))

    def seal_with_distinct_saved_timings(*args, **kwargs):
        row = original(*args, **kwargs)
        encryption_ns, hashing_ns, signing_ns = next(elapsed)
        row.update(encryption_ns=encryption_ns, hashing_ns=hashing_ns, signing_ns=signing_ns)
        return row

    monkeypatch.setattr(records, "seal_record", seal_with_distinct_saved_timings)
    first = _saved(config, keys, body="first version")
    second = records.save_record(
        config, keys, owner="alice", record_id=first["id"],
        title="Second version has different size", body="second version is longer",
        src_ip="192.0.2.10", session_ref="test-session",
    )
    response = real_storage_client.get(f"/records/{second['id']}", base_url="https://localhost")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Saved measurements by version" in html
    assert "Version 1" in html and "Version 2" in html
    for row, values in ((first, ("1100", "2100", "3100")),
                        (second, ("4100", "5100", "6100"))):
        for value in (str(row["plaintext_bytes"]), str(row["ciphertext_bytes"]),
                      str(row["envelope_bytes"]), *values):
            assert value in html


def test_record_forms_offer_multipart_png_jpeg_upload_and_edit_actions(real_storage_client, config, keys):
    _login(real_storage_client)
    create = real_storage_client.get("/records/new", base_url="https://localhost")
    assert create.status_code == 200
    create_html = create.get_data(as_text=True)
    assert 'enctype="multipart/form-data"' in create_html
    assert 'type="file"' in create_html
    assert 'name="image"' in create_html
    assert 'accept="image/png,image/jpeg"' in create_html
    assert 'name="image_action"' in create_html
    assert "record-evidence.js" in create_html
    assert "If JavaScript is disabled" in create_html
    assert "select Add the selected image" in create_html

    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    edit = real_storage_client.get(f"/records/{saved['id']}/edit", base_url="https://localhost")
    assert edit.status_code == 200
    edit_html = edit.get_data(as_text=True)
    assert 'enctype="multipart/form-data"' in edit_html
    assert 'name="image"' in edit_html
    assert 'accept="image/png,image/jpeg"' in edit_html
    for action in ("keep", "replace", "remove"):
        assert re.search(
            rf'<[^>]+name="image_action"[^>]+value="{action}"|'
            rf'<[^>]+value="{action}"[^>]+name="image_action"', edit_html,
        ), edit_html

    script = (_TEMPLATE_ROOT.parent / "static" / "record-evidence.js").read_text(encoding="utf-8")
    assert re.search(r'addEventListener\(["\']change["\']', script)
    assert re.search(r'input\[name=["\']image["\']\]', script)
    assert re.search(r'input\[name=["\']image_action["\']\]\[value=["\']replace["\']\]', script)
    assert re.search(r'\.checked\s*=\s*true', script)


def test_latest_and_historical_image_links_are_shown_only_for_image_versions(
    real_storage_client, config, keys,
):
    _login(real_storage_client)
    png = _image()
    first = _saved(config, keys, title="Old image", image_bytes=png, image_mime="image/png")
    removed = records.save_record(
        config, keys, owner="alice", record_id=first["id"], title="Text only",
        body="No image in this version", src_ip="192.0.2.10", session_ref="test-session",
        image_action="remove",
    )
    latest = records.save_record(
        config, keys, owner="alice", record_id=first["id"], title="Latest image",
        body="Latest body", src_ip="192.0.2.10", session_ref="test-session",
        image_action="replace", image_bytes=png, image_mime="image/png",
    )

    response = real_storage_client.get(f"/records/{first['id']}", base_url="https://localhost")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for version in (first["version"], latest["version"]):
        prefix = f"/records/{first['id']}/versions/{version}"
        assert prefix + "/image" in html
        assert prefix + "/image-ciphertext" in html
    removed_prefix = f"/records/{first['id']}/versions/{removed['version']}"
    assert removed_prefix + "/image" not in html
    assert removed_prefix + "/image-ciphertext" not in html


def test_image_evidence_escapes_record_labels_and_loads_ciphertext_lazily(
    real_storage_client, config, keys,
):
    _login(real_storage_client)
    label = "<script>alert('image')</script>"
    saved = _saved(config, keys, title=label, image_bytes=_image(), image_mime="image/png")

    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "&lt;script&gt;alert(&#39;image&#39;)&lt;/script&gt;" in html
    assert label not in html
    assert "record-evidence.js" in html
    ciphertext_url = f"/records/{saved['id']}/versions/{saved['version']}/image-ciphertext"
    assert ciphertext_url in html
    assert base64.b64encode(saved["image_ciphertext"]).decode("ascii") not in html

    script = (_TEMPLATE_ROOT.parent / "static" / "record-evidence.js").read_text(encoding="utf-8")
    assert "fetch(" in script
    assert "textContent" in script
    assert "toggle" in script


def test_image_version_evidence_shows_signed_metadata_and_saved_image_timings(
    real_storage_client, config, keys,
):
    _login(real_storage_client)
    image = _image()
    first = _saved(config, keys, image_bytes=image, image_mime="image/png")
    latest = records.save_record(
        config, keys, owner="alice", record_id=first["id"], title="Kept image",
        body="Image retained", src_ip="192.0.2.10", session_ref="test-session",
    )
    response = real_storage_client.get(f"/records/{first['id']}", base_url="https://localhost")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    rows = _rows(config, "record_versions")

    for row in rows:
        assert row["image_mime"] in html
        assert str(row["image_size"]) in html
        assert base64.b64encode(row["image_nonce"]).decode("ascii") in html
        assert row["image_plain_sha256"] in html
        assert row["image_cipher_sha256"] in html
        for timing in (row["image_encrypt_ns"], row["image_hash_ns"]):
            assert str(timing) in html or f"{timing / 1_000_000:.6f}" in html
        assert row["signature_b64"] in html
    assert rows[0]["version"] == first["version"]
    assert rows[-1]["version"] == latest["version"]


def test_full_ciphertext_uses_separate_status_live_region(real_storage_client, config, keys):
    _login(real_storage_client)
    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    output = re.search(r'<pre\b(?=[^>]*data-ciphertext-output)[^>]*>', html)
    assert output
    assert "aria-live" not in output.group(0)
    assert re.search(
        r'<(?:p|span|div)\b(?=[^>]*data-ciphertext-status)(?=[^>]*aria-live="polite")[^>]*>',
        html,
    )


def test_existing_text_evidence_and_saved_timings_remain_visible_with_image(
    real_storage_client, config, keys, monkeypatch,
):
    _login(real_storage_client)
    original = records.seal_record

    def seal_with_fixed_timings(*args, **kwargs):
        row = original(*args, **kwargs)
        row.update(encryption_ns=60, hashing_ns=20, signing_ns=50)
        return row

    monkeypatch.setattr(records, "seal_record", seal_with_fixed_timings)
    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    response = real_storage_client.get(f"/records/{saved['id']}", base_url="https://localhost")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for value in (saved["ciphertext_b64"], saved["nonce_b64"], saved["sha256_hex"],
                  saved["signature_b64"], "0.000060", "0.000020", "0.000050"):
        assert value in html
    assert "Envelope hash verification passed" in html
    assert "Digital signature verification passed" in html
    assert "Measured operation durations for this saved version" in html


def test_foreign_record_evidence_is_not_rendered(real_storage_client, config, keys):
    _login(real_storage_client)
    foreign = _saved(config, keys, owner="bob")

    response = real_storage_client.get(f"/records/{foreign['id']}", base_url="https://localhost")

    assert response.status_code == 403
    html = response.get_data(as_text=True)
    assert foreign["ciphertext_b64"] not in html
    assert foreign["nonce_b64"] not in html
    assert foreign["sha256_hex"] not in html
    assert foreign["signature_b64"] not in html


def test_owner_version_image_preview_and_full_ciphertext_have_private_headers(
    real_storage_client, config, keys,
):
    _login(real_storage_client)
    png = _image()
    first = _saved(config, keys, image_bytes=png, image_mime="image/png")
    second = records.save_record(
        config, keys, owner="alice", record_id=first["id"], title="Edited title",
        body="Edited body", src_ip="192.0.2.10", session_ref="test-session",
    )
    for row in (first, second):
        prefix = f"/records/{first['id']}/versions/{row['version']}/image"
        preview = real_storage_client.get(prefix, base_url="https://localhost")
        assert preview.status_code == 200
        assert preview.data == png
        assert preview.mimetype == "image/png"
        _assert_private_image_headers(preview)

        ciphertext = real_storage_client.get(prefix + "-ciphertext", base_url="https://localhost")
        assert ciphertext.status_code == 200
        assert ciphertext.mimetype == "text/plain"
        assert ciphertext.get_data(as_text=True).strip() == base64.b64encode(
            row["image_ciphertext"]
        ).decode("ascii")
        _assert_private_image_headers(ciphertext)


@pytest.mark.parametrize("suffix", ["/image", "/image-ciphertext"])
def test_image_routes_deny_foreign_owner_without_disclosing_evidence(
    real_storage_client, config, keys, suffix,
):
    _login(real_storage_client)
    image = _image()
    foreign = _saved(config, keys, owner="bob", image_bytes=image, image_mime="image/png")
    response = real_storage_client.get(
        f"/records/{foreign['id']}/versions/1{suffix}", base_url="https://localhost",
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 403
    _assert_private_image_headers(response)
    assert image not in response.data
    assert base64.b64encode(foreign["image_ciphertext"]) not in response.data
    assert foreign["image_plain_sha256"].encode("ascii") not in response.data
    assert _rows(config, "records") == [foreign]
    denial = _rows(config, "events")[-1]
    assert verify_app_event(keys, denial)
    assert (denial["kind"], denial["username"], denial["record_id"]) == (
        "foreign_record_denied", "alice", foreign["id"],
    )


@pytest.mark.parametrize("suffix", ["/image", "/image-ciphertext"])
def test_image_routes_return_404_for_absent_image_or_version(
    real_storage_client, config, keys, suffix,
):
    _login(real_storage_client)
    text_only = _saved(config, keys)
    for version in (1, 2):
        response = real_storage_client.get(
            f"/records/{text_only['id']}/versions/{version}{suffix}",
            base_url="https://localhost",
        )
        assert response.status_code == 404
        _assert_private_image_headers(response)
    missing = real_storage_client.get(
        f"/records/{'f' * 32}/versions/1{suffix}", base_url="https://localhost",
    )
    assert missing.status_code == 404
    _assert_private_image_headers(missing)


@pytest.mark.parametrize("suffix", ["/image", "/image-ciphertext"])
def test_corrupt_old_image_blocks_current_version_route_without_partial_response(
    real_storage_client, config, keys, suffix,
):
    _login(real_storage_client)
    image = _image()
    first = _saved(config, keys, image_bytes=image, image_mime="image/png")
    current = records.save_record(
        config, keys, owner="alice", record_id=first["id"], title="Current secret",
        body="Current body", src_ip="192.0.2.10", session_ref="test-session",
    )
    with transaction(config) as conn:
        conn.execute(
            "UPDATE record_versions SET image_ciphertext=? WHERE id=? AND version=1",
            (b"\x00" + first["image_ciphertext"][1:], first["id"]),
        )
    response = real_storage_client.get(
        f"/records/{first['id']}/versions/{current['version']}{suffix}",
        base_url="https://localhost", environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 409
    _assert_private_image_headers(response)
    assert image not in response.data
    assert b"Current secret" not in response.data
    assert base64.b64encode(current["image_ciphertext"]) not in response.data
    failure = _rows(config, "events")[-1]
    assert verify_app_event(keys, failure)
    assert (failure["kind"], failure["username"], failure["record_id"]) == (
        "integrity_failure", "alice", first["id"],
    )


@pytest.mark.parametrize("suffix", ["/image", "/image-ciphertext"])
def test_unauthenticated_image_route_redirect_is_private(real_storage_client, config, keys, suffix):
    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    response = real_storage_client.get(
        f"/records/{saved['id']}/versions/1{suffix}",
        base_url="https://localhost", follow_redirects=False,
    )
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/login")
    _assert_private_image_headers(response)
    assert saved["image_ciphertext"] not in response.data


@pytest.mark.parametrize("suffix", ["/image", "/image-ciphertext"])
def test_blocked_ip_image_route_denial_is_private(real_storage_client, config, keys, suffix):
    _login(real_storage_client)
    saved = _saved(config, keys, image_bytes=_image(), image_mime="image/png")
    with transaction(config) as conn:
        conn.execute(
            "INSERT INTO blocks(ip,created_at_us,created_by,reason) VALUES (?,?,?,?)",
            ("192.0.2.10", 1, "admin", "Test block"),
        )
    response = real_storage_client.get(
        f"/records/{saved['id']}/versions/1{suffix}",
        base_url="https://localhost", environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 403
    _assert_private_image_headers(response)
    assert saved["image_ciphertext"] not in response.data


@pytest.mark.parametrize("path_suffix", ["", "/edit"])
def test_sensitive_detail_and_edit_get_have_no_store(real_storage_client, config, keys, path_suffix):
    _login(real_storage_client)
    saved = _saved(config, keys)
    response = real_storage_client.get(
        f"/records/{saved['id']}{path_suffix}", base_url="https://localhost",
    )
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]


def test_storage_accepts_image_multipart_larger_than_prior_text_request_limit(
    real_storage_client, config, keys,
):
    _login(real_storage_client)
    image = _image(large=True)
    assert 65_536 < len(image) < 1_048_576
    response = _image_post(real_storage_client, "/records/new", image_action="replace", content=image)
    assert response.status_code == 303
    rows = _rows(config, "records")
    assert len(rows) == 1
    assert rows[0]["image_mime"] == "image/png"
    assert open_record_image(keys, rows[0]) == ("image/png", image)
    assert _rows(config, "record_versions") == rows
    event = _rows(config, "events")[-1]
    assert event["kind"] == "record_created" and verify_app_event(keys, event)


def test_storage_edit_upload_actions_keep_replace_and_remove(real_storage_client, config, keys):
    _login(real_storage_client)
    png = _image()
    jpeg = _image("JPEG")
    created = _image_post(real_storage_client, "/records/new", image_action="replace", content=png)
    assert created.status_code == 303
    record_id = _rows(config, "records")[0]["id"]
    path = f"/records/{record_id}/edit"
    for action, content, mime in (("keep", None, "image/png"),
                                  ("replace", jpeg, "image/jpeg"),
                                  ("remove", None, "image/png")):
        response = _image_post(real_storage_client, path, image_action=action, content=content, mime=mime)
        assert response.status_code == 303
    versions = _rows(config, "record_versions")
    assert [open_record_image(keys, row) for row in versions] == [
        ("image/png", png), ("image/png", png), ("image/jpeg", jpeg), None,
    ]
    assert versions[0]["image_nonce"] != versions[1]["image_nonce"]
    assert _rows(config, "records") == [versions[-1]]
    events = _rows(config, "events")
    assert [row["kind"] for row in events] == [
        "login_success", "record_created", "record_updated", "record_updated", "record_updated",
    ]
    assert all(verify_app_event(keys, event) for event in events[1:])


@pytest.mark.parametrize(
    "content", [b"not a PNG", b"x" * 1_048_577], ids=["malformed", "oversize"],
)
@pytest.mark.parametrize("editing", [False, True])
def test_rejected_image_upload_keeps_record_versions_and_success_audit_unchanged(
    real_storage_client, config, keys, content, editing,
):
    _login(real_storage_client)
    saved = _saved(config, keys) if editing else None
    before = {table: _rows(config, table) for table in ("records", "record_versions", "events")}
    response = _image_post(
        real_storage_client, f"/records/{saved['id']}/edit" if saved else "/records/new",
        image_action="replace", content=content,
    )
    assert response.status_code in (400, 413)
    for table, expected in before.items():
        assert _rows(config, table) == expected
