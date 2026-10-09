from dataclasses import replace

import pytest

from security_lab.config import load_config


@pytest.fixture
def config(tmp_path):
    """Use an isolated database directory for every test."""
    return replace(load_config({}), data_dir=tmp_path / "data")
