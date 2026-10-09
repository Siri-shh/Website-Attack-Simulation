from dataclasses import replace

import pytest

from security_lab.config import load_config


@pytest.fixture
def config(tmp_path):
    """Use an isolated database directory for every test."""
    return replace(load_config({}), data_dir=tmp_path / "data")


@pytest.fixture
def keys(config):
    """Initialize isolated storage before creating its persistent test keys."""
    from security_lab.db import initialize_database
    from security_lab.identity import load_or_create_keys

    initialize_database(config)
    return load_or_create_keys(config)


@pytest.fixture
def storage_app(config, keys):
    """Build storage with seeded demo identities and test-only template stubs."""
    from jinja2 import DictLoader
    from werkzeug.security import generate_password_hash

    from security_lab.db import transaction
    from security_lab.storage import create_storage_app

    with transaction(config) as conn:
        conn.executemany(
            "INSERT INTO users(username,role,password_hash,created_at_us) VALUES(?,?,?,?)",
            [
                ("alice", "user", generate_password_hash("AlicePass!2026", method="scrypt"), 1),
                ("bob", "user", generate_password_hash("BobPass!2026", method="scrypt"), 2),
            ],
        )

    app = create_storage_app(config, keys)
    app.config.update(TESTING=True)
    app.jinja_loader = DictLoader({
        "login.html": """<!doctype html><form method="post"><input name="csrf_token" value="{{ csrf_token() }}"></form>""",
        "storage/list.html": """<!doctype html><h1>{{ username }}</h1>{% for message in get_flashed_messages() %}<p class="flash">{{ message }}</p>{% endfor %}{% for record in records %}<p>{{ record.title }}</p>{% endfor %}<input name="csrf_token" value="{{ csrf_token }}">""",
        "storage/form.html": """<!doctype html><h1>{{ username }}</h1><p>{{ record_id }}</p><p>{{ error }}</p><input name="csrf_token" value="{{ csrf_token }}"><textarea>{{ form.title }} {{ form.body }}</textarea>""",
        "storage/detail.html": """<!doctype html><h1>{{ username }}</h1><p>{{ plaintext.title }}|{{ plaintext.body }}</p><p>{{ record.id }}|{{ record.ciphertext_b64 }}</p><p>{{ verified }}</p><input name="csrf_token" value="{{ csrf_token }}">""",
    })
    return app


@pytest.fixture
def storage_client(storage_app):
    """Return an HTTPS test client for the storage app."""
    return storage_app.test_client()
