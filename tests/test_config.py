import pytest

from security_lab.config import Config, format_ist, format_utc, load_config, normalize_ip, utc_us


def test_defaults():
    cfg = load_config({})
    assert isinstance(cfg, Config)
    assert cfg.storage_port == 8443
    assert cfg.console_port == 8444
    assert cfg.data_dir.is_absolute()
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.server_ip == "127.0.0.1"
    assert cfg.capture_interface is None
    assert cfg.tls_names == ("localhost", "127.0.0.1")


def test_distinct_ports():
    with pytest.raises(ValueError):
        load_config({"LAB_STORAGE_PORT": "8443", "LAB_CONSOLE_PORT": "8443"})


def test_utc_and_mapped_ip():
    assert format_utc(0) == "1970-01-01T00:00:00.000000Z"
    assert format_ist(0) == "1970-01-01T05:30:00.000000+05:30"
    assert format_ist(1_000_001) == "1970-01-01T05:30:01.000001+05:30"
    assert normalize_ip("::ffff:192.168.1.2") == "192.168.1.2"


def test_mapping_is_the_only_environment_source(monkeypatch):
    monkeypatch.setenv("LAB_STORAGE_PORT", "9001")
    cfg = load_config({"LAB_CONSOLE_PORT": "9002"})
    assert (cfg.storage_port, cfg.console_port) == (8443, 9002)


@pytest.mark.parametrize("name", ["LAB_STORAGE_PORT", "LAB_CONSOLE_PORT"])
@pytest.mark.parametrize("value", ["0", "65536", "-1"])
def test_ports_must_be_in_range(name, value):
    with pytest.raises(ValueError):
        load_config({name: value})


@pytest.mark.parametrize("name", ["LAB_BIND_HOST", "LAB_SERVER_IP"])
def test_configured_addresses_must_be_ip_literals(name):
    with pytest.raises(ValueError):
        load_config({name: "example.invalid"})


def test_explicit_missing_tshark_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_config({"LAB_TSHARK": str(tmp_path / "missing-tshark")})


def test_missing_default_tshark_is_tolerated(monkeypatch):
    import security_lab.config as config_module

    monkeypatch.setattr(config_module.shutil, "which", lambda _: None)
    monkeypatch.setattr(config_module.Path, "is_file", lambda _: False)
    cfg = load_config({})
    assert cfg.tshark_path == "tshark"


def test_tls_names_are_deduplicated_in_order():
    cfg = load_config({"LAB_TLS_NAMES": "lab.local, 127.0.0.1,lab.local"})
    assert cfg.tls_names == ("lab.local", "127.0.0.1")


def test_utc_us_is_positive_integer():
    value = utc_us()
    assert isinstance(value, int)
    assert value > 0
