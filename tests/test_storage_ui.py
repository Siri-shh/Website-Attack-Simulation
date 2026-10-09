"""Owner-only evidence and saved-operation timing presentation tests."""

from pathlib import Path
import re

import pytest
from jinja2 import FileSystemLoader

from security_lab import records
from security_lab.config import format_ist


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


def _saved(config, keys, *, owner="alice", title="Evidence title", body="Evidence body"):
    return records.save_record(
        config,
        keys,
        owner=owner,
        record_id=None,
        title=title,
        body=body,
        src_ip="192.0.2.10",
        session_ref="test-session",
    )


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
    paths = [f"/records/{saved['id']}"] * 2
    responses = [real_storage_client.get(path, base_url="https://localhost") for path in paths]

    assert all(response.status_code == 200 for response in responses)
    html = [response.get_data(as_text=True) for response in responses]
    assert all("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;" in page for page in html)
    assert all("<script>alert('x')</script>" not in page for page in html)
    assert all("0.000060" in page for page in html)
    assert all("0.000020" in page for page in html)
    assert all("0.000050" in page for page in html)
    assert all(saved["nonce_b64"] in page and saved["signature_b64"] in page for page in html)
    assert all("Measured operation durations for this saved version" in page for page in html)
    assert html[0] == html[1]


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
