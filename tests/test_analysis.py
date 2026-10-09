"""Tests for the isolated, bounded crypto analysis helpers."""

import pytest

from security_lab import analysis


def test_aes_gcm_analysis_uses_unique_nonces_and_recovers_input(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAESGCM

    calls = {"encrypt": [], "decrypt": []}

    def random_bytes(size):
        return bytes([size]) * size

    class RecordingAESGCM:
        def __init__(self, key):
            self.inner = RealAESGCM(key)

        def encrypt(self, nonce, data, aad):
            calls["encrypt"].append(nonce)
            return self.inner.encrypt(nonce, data, aad)

        def decrypt(self, nonce, data, aad):
            calls["decrypt"].append(nonce)
            return self.inner.decrypt(nonce, data, aad)

    clock_calls = 0
    previous = 1_000_000

    def now_ns():
        nonlocal clock_calls, previous
        clock_calls += 1
        if clock_calls % 2:
            return previous
        sample = (clock_calls // 2) - 1
        duration = sample + 1 if sample < 1000 else sample + 1
        previous += duration
        return previous

    monkeypatch.setattr(analysis, "_random_bytes", random_bytes)
    monkeypatch.setattr(analysis, "AESGCM", RecordingAESGCM)
    monkeypatch.setattr(analysis, "_now_ns", now_ns)
    result = analysis.aes_gcm_analysis(b"analysis input")

    assert result["input_bytes"] == len(b"analysis input")
    assert result["warmup_pairs"] == 20
    assert result["timed_encryptions"] == result["timed_decryptions"] == 1000
    assert result["ciphertext_bytes"] == len(b"analysis input") + 16
    assert result["tag_bytes"] == 16
    assert result["plaintext_matches"] is True
    assert result["recovered_text"] == "analysis input"
    assert len(bytes.fromhex(result["sample_nonce_hex"])) == 12
    assert len(bytes.fromhex(result["sample_ciphertext_hex"])) == len(b"analysis input") + 16
    assert len(calls["encrypt"]) == len(calls["decrypt"]) == 1020
    assert len(set(calls["encrypt"])) == 1020
    assert clock_calls == 4000  # warm-up pairs are outside timed intervals
    assert result["encryption_timing_ns"] == {"median": 500.5, "p95": 950}
    assert result["decryption_timing_ns"] == {"median": 1500.5, "p95": 1950}


def test_sha256_analysis_is_bounded_and_reports_full_digest(monkeypatch):
    ticks = iter(range(100, 1000, 10))
    monkeypatch.setattr(analysis, "_now_ns", lambda: next(ticks))
    result = analysis.sha256_analysis(b"source", candidate_limit=3)

    assert len(result["target_digest_hex"]) == 64
    for name in ("preimage", "second_preimage", "collision"):
        panel = result[name]
        assert panel["budget"] == 3
        assert panel["attempts"] == 3
        assert panel["elapsed_ns"] == 10
        assert panel["found"] is False
    assert result["preimage"]["candidate_hex"] is None
    assert result["second_preimage"]["candidate_hex"] is None
    assert result["collision"]["first_candidate_hex"] is None
    assert result["collision"]["second_candidate_hex"] is None
    assert result["collision"]["digest_hex"] is None


def test_preimage_skips_source_candidate_without_spending_hash_budget(monkeypatch):
    random_value = bytes(32)
    source = b"sha256-preimage\x00" + bytes(8) + random_value
    monkeypatch.setattr(analysis, "_random_bytes", lambda size: random_value)
    monkeypatch.setattr(analysis, "_digest", lambda data: b"T" * 32)

    result = analysis.sha256_analysis(source, candidate_limit=1)

    next_candidate = b"sha256-preimage\x00" + (1).to_bytes(8, "big") + random_value
    assert result["preimage"]["attempts"] == 1
    assert result["preimage"]["found"] is True
    assert result["preimage"]["candidate_hex"] == next_candidate.hex()


def test_sha256_searches_report_deterministic_successes_and_stop_early(monkeypatch):
    random_calls = 0

    def random_bytes(size):
        nonlocal random_calls
        random_calls += 1
        return bytes([random_calls]) * size

    def digest(data):
        if data == b"source":
            return b"T" * 32
        if data.startswith((b"sha256-preimage\x00", b"source\x00sha256-second-preimage\x00")):
            return b"T" * 32
        if data.startswith(b"sha256-collision\x00"):
            return b"C" * 32
        return b"X" * 32

    monkeypatch.setattr(analysis, "_random_bytes", random_bytes)
    monkeypatch.setattr(analysis, "_digest", digest)
    result = analysis.sha256_analysis(b"source", candidate_limit=5)

    preimage = b"sha256-preimage\x00" + bytes(8) + bytes([1]) * 32
    second_preimage = b"source\x00sha256-second-preimage\x00" + bytes(8)
    collision_a = b"sha256-collision\x00" + bytes(8) + bytes([2]) * 32
    collision_b = b"sha256-collision\x00" + (1).to_bytes(8, "big") + bytes([3]) * 32
    assert result["preimage"]["attempts"] == 1
    assert result["preimage"]["candidate_hex"] == preimage.hex()
    assert result["second_preimage"]["attempts"] == 1
    assert result["second_preimage"]["candidate_hex"] == second_preimage.hex()
    assert result["collision"]["attempts"] == 2
    assert result["collision"]["first_candidate_hex"] == collision_a.hex()
    assert result["collision"]["second_candidate_hex"] == collision_b.hex()
    assert collision_a != collision_b
    assert result["collision"]["digest_hex"] == (b"C" * 32).hex()


@pytest.mark.parametrize("limit", [True, False, 0, -1, 10001, 1.5, "3"])
def test_sha256_analysis_rejects_invalid_candidate_limits(limit):
    with pytest.raises((TypeError, ValueError)):
        analysis.sha256_analysis(b"x", candidate_limit=limit)


def test_aes_primitive_analysis_reports_fixed_workload_and_sac_matrix(monkeypatch):
    from cryptography.hazmat.primitives.ciphers import Cipher as RealCipher

    encryptions = 0

    class RecordingCipher:
        def __init__(self, algorithm, mode):
            self.inner = RealCipher(algorithm, mode)

        def encryptor(self):
            nonlocal encryptions
            inner = self.inner.encryptor()

            class RecordingEncryptor:
                def update(self, data):
                    nonlocal encryptions
                    encryptions += 1
                    return inner.update(data)

            return RecordingEncryptor()

    monkeypatch.setattr(analysis, "Cipher", RecordingCipher)
    result = analysis.aes_primitive_analysis(b"sixteen byte msg")

    assert result["keys_tested"] == 32
    assert result["baseline_encryptions"] == 32
    assert result["plaintext_comparisons"] == 4096
    assert result["key_comparisons"] == 8192
    assert result["total_encryptions"] == 12320
    assert encryptions == 12320
    assert len(bytes.fromhex(result["block_hex"])) == 16
    assert len(result["sac"]["flip_percentages"]) == 128
    assert all(len(row) == 128 for row in result["sac"]["flip_percentages"])
    assert 0 <= result["sac"]["min_flip_percent"] <= result["sac"]["max_flip_percent"] <= 100


@pytest.mark.parametrize("func", [analysis.aes_gcm_analysis, analysis.sha256_analysis, analysis.aes_primitive_analysis])
def test_analysis_rejects_non_bytes_and_oversized_input(func):
    with pytest.raises(TypeError):
        func("text")
    with pytest.raises(ValueError):
        func(b"x" * (analysis.MAX_INPUT_BYTES + 1))
