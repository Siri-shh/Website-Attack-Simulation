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
