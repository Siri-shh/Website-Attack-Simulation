"""Storage route contracts with a test-only template loader."""

from contextlib import closing
import re
from urllib.parse import urlsplit

import pytest

from security_lab import records
from security_lab.db import connect


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


def _saved_record(config, keys, *, owner="alice"):
    return records.save_record(
        config, keys, owner=owner, record_id=None, title="Saved title",
        body="Saved private body", src_ip="192.0.2.10", session_ref="test-session",
    )


def test_unauthenticated_storage_list_redirects_to_login(storage_client):
    response = storage_client.get("/", base_url="https://localhost", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert urlsplit(response.headers["Location"]).path == "/login"


def test_login_create_and_edit_use_csrf_and_redirect_303(storage_client):
    _login(storage_client)
    listing = storage_client.get("/", base_url="https://localhost")
    assert listing.status_code == 200
    assert b"Login successful" in listing.data

    token = _csrf(storage_client, "/records/new")
    created = storage_client.post(
        "/records/new",
        base_url="https://localhost",
        data={"csrf_token": token, "title": "First title", "body": "First body"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    detail_path = urlsplit(created.headers["Location"]).path
    assert re.fullmatch(r"/records/[0-9a-f]{32}", detail_path)

    token = _csrf(storage_client, detail_path + "/edit")
    edited = storage_client.post(
        detail_path + "/edit",
        base_url="https://localhost",
        data={"csrf_token": token, "title": "Updated title", "body": "Updated body"},
        follow_redirects=False,
    )
    assert edited.status_code == 303
    assert urlsplit(edited.headers["Location"]).path == detail_path


def test_record_detail_uses_read_service_and_renders_saved_evidence(storage_client, config, keys, monkeypatch):
    _login(storage_client)
    saved = _saved_record(config, keys)
    original = records.read_record
    calls = []

    def read_spy(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr("security_lab.storage.read_record", read_spy)
    response = storage_client.get(
        f"/records/{saved['id']}", base_url="https://localhost",
        environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
    )
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0][1]["owner"] == "alice"
    assert calls[0][1]["record_id"] == saved["id"]
    assert b"Saved title|Saved private body" in response.data
    assert saved["ciphertext_b64"].encode("ascii") in response.data
    assert b"True" in response.data


def test_foreign_record_view_and_edit_are_forbidden(storage_client, config, keys):
    _login(storage_client)
    foreign = _saved_record(config, keys, owner="bob")
    detail_path = f"/records/{foreign['id']}"
    assert storage_client.get(detail_path, base_url="https://localhost").status_code == 403
    assert storage_client.get(detail_path + "/edit", base_url="https://localhost").status_code == 403

    token = _csrf(storage_client, "/records/new")
    response = storage_client.post(
        detail_path + "/edit",
        base_url="https://localhost",
        data={"csrf_token": token, "title": "Forged", "body": "Forbidden"},
    )
    assert response.status_code == 403


def test_missing_record_ids_return_404_for_detail_and_edit(storage_client):
    _login(storage_client)
    missing = "f" * 32
    assert storage_client.get(f"/records/{missing}", base_url="https://localhost").status_code == 404
    assert storage_client.get(f"/records/{missing}/edit", base_url="https://localhost").status_code == 404


def test_create_and_edit_without_csrf_return_400(storage_client, config, keys):
    _login(storage_client)
    assert storage_client.post(
        "/records/new", base_url="https://localhost",
        data={"title": "Title", "body": "Body"},
    ).status_code == 400
    saved = _saved_record(config, keys)
    assert storage_client.post(
        f"/records/{saved['id']}/edit", base_url="https://localhost",
        data={"title": "Title", "body": "Body"},
    ).status_code == 400


def test_oversized_storage_post_returns_413(storage_client):
    _login(storage_client)
    token = _csrf(storage_client, "/records/new")
    response = storage_client.post(
        "/records/new",
        base_url="https://localhost",
        data={"csrf_token": token, "title": "Large", "body": "x" * 65_537},
    )
    assert response.status_code == 413



def test_error_template_context_includes_message_for_each_error_status(
    storage_client, storage_app, config, keys
):
    """Exercise required error-message context alongside each frozen status mapping."""
    from flask import template_rendered

    from security_lab.db import transaction

    _login(storage_client)
    token = _csrf(storage_client, "/records/new")
    rendered = []

    def capture(sender, template, context, **extra):
        rendered.append((template.name, dict(context)))

    template_rendered.connect(capture, sender=storage_app, weak=False)
    try:
        cases = []

        before = len(rendered)
        invalid = storage_client.post(
            "/records/new", base_url="https://localhost",
            data={"csrf_token": token, "title": "  ", "body": "Valid body"},
        )
        cases.append((400, invalid, rendered[before:]))

        foreign = _saved_record(config, keys, owner="bob")
        before = len(rendered)
        denied = storage_client.get(
            f"/records/{foreign['id']}", base_url="https://localhost",
        )
        cases.append((403, denied, rendered[before:]))

        before = len(rendered)
        missing = storage_client.get(
            f"/records/{'f' * 32}", base_url="https://localhost",
        )
        cases.append((404, missing, rendered[before:]))

        corrupted = _saved_record(config, keys)
        with transaction(config) as conn:
            conn.execute(
                "UPDATE records SET ciphertext_b64=? WHERE id=?",
                ("!", corrupted["id"]),
            )
        before = len(rendered)
        integrity = storage_client.get(
            f"/records/{corrupted['id']}", base_url="https://localhost",
        )
        cases.append((409, integrity, rendered[before:]))
    finally:
        template_rendered.disconnect(capture, sender=storage_app)

    for expected_status, response, captures in cases:
        assert response.status_code == expected_status
        template_contexts = [
            context for name, context in captures if name == "storage/form.html"
        ]
        assert template_contexts
        context = template_contexts[-1]
        assert context["message"] == context["error"]
        assert context["message"]
