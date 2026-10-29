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
    monkeypatch.setattr(analysis, "_random_bytes", lambda size: bytes([0x35]) * size)
    result = analysis.aes_primitive_analysis(b"sixteen byte msg")

    assert result["keys_tested"] == 32
    assert result["baseline_encryptions"] == 32
    assert result["plaintext_comparisons"] == 4096
    assert result["key_comparisons"] == 8192
    assert result["total_encryptions"] == 12320
    assert encryptions == 12320
    for summary_name, comparison_count in (("plaintext_avalanche", 4096), ("key_avalanche", 8192)):
        summary = result[summary_name]
        assert {
            "mean_changed_bits", "min_changed_bits", "max_changed_bits",
            "mean_changed_percent", "min_changed_percent", "max_changed_percent",
        } <= set(summary)
        bins = summary["distribution_10pct"]
        assert len(bins) == 10
        assert [item["lower_percent"] for item in bins] == list(range(0, 100, 10))
        assert [item["upper_percent"] for item in bins] == list(range(10, 101, 10))
        assert all(type(item["count"]) is int and item["count"] >= 0 for item in bins)
        assert sum(item["count"] for item in bins) == comparison_count
    assert len(bytes.fromhex(result["block_hex"])) == 16
    assert len(result["sac"]["flip_percentages"]) == 128
    assert all(len(row) == 128 for row in result["sac"]["flip_percentages"])
    assert 0 <= result["sac"]["min_flip_percent"] <= result["sac"]["max_flip_percent"] <= 100

    # Compare corresponding hex characters of the baseline and a one-bit
    # plaintext change under the same key, not bits or two different keys.
    from cryptography.hazmat.primitives.ciphers import algorithms, modes

    key = bytes([0x35]) * 32
    block = bytes.fromhex(result["block_hex"])
    changed_block = bytes([block[0] ^ 0x80]) + block[1:]
    baseline = RealCipher(algorithms.AES(key), modes.ECB()).encryptor().update(block).hex()
    changed = RealCipher(algorithms.AES(key), modes.ECB()).encryptor().update(changed_block).hex()
    changed_characters = sum(left != right for left, right in zip(baseline, changed))
    assert result["hex_character_change"] == {
        "changed": changed_characters,
        "total": 32,
        "percent": pytest.approx(changed_characters * 100 / 32),
    }

    summary = result["sac"]["summary_16x16"]
    assert len(summary) == 16 and all(len(row) == 16 for row in summary)
    original = result["sac"]["flip_percentages"]
    for row_index in range(16):
        for column_index in range(16):
            block_values = [
                original[row][column]
                for row in range(row_index * 8, row_index * 8 + 8)
                for column in range(column_index * 8, column_index * 8 + 8)
            ]
            assert summary[row_index][column_index] == pytest.approx(sum(block_values) / 64)


def test_avalanche_distribution_has_ordered_10_percent_bins_and_inclusive_last_bin():
    # 0 and 128 changed bits are the endpoint percentages; 64 is exactly 50%.
    # Counts adjacent to 10% and 90% show the half-open bin boundaries.
    summary = analysis._avalanche_summary([0, 12, 13, 64, 115, 116, 128])

    assert set(summary) == {
        "mean_changed_bits", "min_changed_bits", "max_changed_bits",
        "mean_changed_percent", "min_changed_percent", "max_changed_percent",
        "distribution_10pct",
    }
    assert summary["min_changed_bits"] == 0
    assert summary["max_changed_bits"] == 128
    assert summary["mean_changed_bits"] == pytest.approx(448 / 7)
    bins = summary["distribution_10pct"]
    assert bins == [
        {"lower_percent": lower, "upper_percent": lower + 10, "count": count}
        for lower, count in zip(range(0, 100, 10), (2, 1, 0, 0, 0, 1, 0, 0, 1, 2))
    ]


def test_size_sweep_uses_approved_sizes_and_100_samples_with_correct_units(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAESGCM

    calls = {"encrypt": [], "decrypt": []}

    class RecordingAESGCM:
        def __init__(self, key):
            assert len(key) == 32
            self.inner = RealAESGCM(key)

        def encrypt(self, nonce, data, aad):
            calls["encrypt"].append((nonce, data))
            return self.inner.encrypt(nonce, data, aad)

        def decrypt(self, nonce, sealed, aad):
            calls["decrypt"].append(nonce)
            return self.inner.decrypt(nonce, sealed, aad)

    ticks = 0

    def clock():
        nonlocal ticks
        ticks += 1
        return (ticks // 2) * 2_000 if ticks % 2 == 0 else ((ticks - 1) // 2) * 2_000

    monkeypatch.setattr(analysis, "AESGCM", RecordingAESGCM)
    monkeypatch.setattr(analysis, "_random_bytes", lambda size: bytes([size % 251]) * size)
    monkeypatch.setattr(analysis, "_now_ns", clock)

    result = analysis.benchmark_size_sweep(sizes=(128, 1024), samples=100)

    assert list(result["sizes"]) == [128, 1024]
    assert result["samples_per_size"] == 100
    assert [point["input_bytes"] for point in result["points"]] == [128, 1024]
    assert ticks == 2 * 5 * 2 * 100  # five timed operations; warm-up is outside samples
    assert len(calls["encrypt"]) > 200  # fixed warm-up occurs before timed samples
    nonces = [nonce for nonce, _ in calls["encrypt"]]
    assert len(nonces) == len(set(nonces))
    assert len(calls["decrypt"]) == len(calls["encrypt"])
    assert calls["decrypt"] == nonces
    for point in result["points"]:
        for operation in ("aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify"):
            values = point[operation]
            assert set(values) == {"median_ns", "p95_ns", "mib_per_s"}
            assert values["median_ns"] == 2_000
            assert values["p95_ns"] == 2_000
            expected_rate = point["input_bytes"] * 1_000_000_000 / (2_000 * 1_048_576)
            assert values["mib_per_s"] == pytest.approx(expected_rate)


def test_size_sweep_median_and_nearest_rank_p95(monkeypatch):
    # Every operation receives four durations even if implementation groups
    # work by operation or by sample.
    durations = iter([1, 2, 3, 100] * 5)
    now = 0
    start = True

    def clock():
        nonlocal now, start
        if start:
            start = False
            return now
        now += next(durations)
        start = True
        return now

    monkeypatch.setattr(analysis, "_now_ns", clock)
    result = analysis.benchmark_size_sweep(sizes=(128,), samples=4)
    values = [result["points"][0][name] for name in (
        "aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify"
    )]
    for item in values:
        assert item["median_ns"] == 2.5
        assert item["p95_ns"] == 100
    assert now == 5 * 106


def test_size_sweep_signs_and_verifies_the_synthetic_input(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as RealEd25519PrivateKey,
    )

    calls = {"generated": 0, "signed": [], "verified": []}

    class RecordingPublicKey:
        def __init__(self, inner):
            self.inner = inner

        def verify(self, signature, data):
            calls["verified"].append((signature, data))
            return self.inner.verify(signature, data)

    class RecordingPrivateKey:
        @classmethod
        def generate(cls):
            calls["generated"] += 1
            return cls(RealEd25519PrivateKey.generate())

        def __init__(self, inner):
            self.inner = inner

        def sign(self, data):
            calls["signed"].append(data)
            return self.inner.sign(data)

        def public_key(self):
            return RecordingPublicKey(self.inner.public_key())

    monkeypatch.setattr(analysis, "Ed25519PrivateKey", RecordingPrivateKey, raising=False)
    monkeypatch.setattr(analysis, "_now_ns", iter(range(0, 1_000_000, 1_000)).__next__)
    result = analysis.benchmark_size_sweep(sizes=(128,), samples=2)

    assert result["points"][0]["input_bytes"] == 128
    assert calls["generated"] >= 1
    assert len(calls["signed"]) > 2  # warm-up is outside the two samples
    assert len(calls["signed"]) == len(calls["verified"])
    assert all(len(data) == 128 for data in calls["signed"])
    for signed_data, (signature, verified_data) in zip(calls["signed"], calls["verified"]):
        assert len(signature) == 64
        assert signed_data == verified_data


def test_size_sweep_detects_failed_aes_round_trip(monkeypatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAESGCM

    class CorruptingAESGCM:
        def __init__(self, key):
            self.inner = RealAESGCM(key)

        def encrypt(self, nonce, data, aad):
            return self.inner.encrypt(nonce, data, aad)

        def decrypt(self, nonce, sealed, aad):
            self.inner.decrypt(nonce, sealed, aad)
            return b"incorrect plaintext"

    monkeypatch.setattr(analysis, "AESGCM", CorruptingAESGCM)
    with pytest.raises(RuntimeError):
        analysis.benchmark_size_sweep(sizes=(128,), samples=1)


@pytest.mark.parametrize("sizes", [(), (0,), (127,), (128, 128), (128, 2048),
                                    (128, 1024, 10240, 102400, 1048576, 128),
                                    [128], (True,), (128.0,)])
def test_size_sweep_rejects_invalid_sizes_before_work(sizes, monkeypatch):
    monkeypatch.setattr(analysis, "_random_bytes", lambda size: pytest.fail("invalid work started"))
    with pytest.raises((TypeError, ValueError)):
        analysis.benchmark_size_sweep(sizes=sizes, samples=1)


@pytest.mark.parametrize("samples", [0, -1, 101, True, False, 1.5, "2"])
def test_size_sweep_rejects_invalid_sample_count_before_work(samples, monkeypatch):
    monkeypatch.setattr(analysis, "_random_bytes", lambda size: pytest.fail("invalid work started"))
    with pytest.raises((TypeError, ValueError)):
        analysis.benchmark_size_sweep(sizes=(128,), samples=samples)


def test_size_sweep_default_uses_exact_approved_grid(monkeypatch):
    monkeypatch.setattr(analysis, "_now_ns", iter(range(0, 10_000_000, 1000)).__next__)
    result = analysis.benchmark_size_sweep(samples=1)
    assert list(result["sizes"]) == [128, 1024, 10240, 102400, 1048576]
    assert [point["input_bytes"] for point in result["points"]] == list(result["sizes"])
    assert result["samples_per_size"] == 1


@pytest.mark.parametrize("func", [analysis.aes_gcm_analysis, analysis.sha256_analysis, analysis.aes_primitive_analysis])
def test_analysis_rejects_non_bytes_and_oversized_input(func):
    with pytest.raises(TypeError):
        func("text")
    with pytest.raises(ValueError):
        func(b"x" * (analysis.MAX_INPUT_BYTES + 1))
