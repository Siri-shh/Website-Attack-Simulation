"""Bounded, in-memory demonstrations for basic cryptographic properties.

These helpers do not access application records, keys, audit facilities, or
identity services. Their measurements are local Python/API observations.
"""

from __future__ import annotations

import hashlib
import math
import os
import statistics
import time
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_INPUT_BYTES = 10240
SWEEP_SIZES = (128, 1024, 10240, 102400, 1048576)
SWEEP_WARMUPS = 5


def _digest(data: bytes) -> bytes:
    """Hash through a small seam so bounded searches can be deterministic in tests."""
    return hashlib.sha256(data).digest()


def _random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _now_ns() -> int:
    return time.perf_counter_ns()


def _check_data(data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"data must be at most {MAX_INPUT_BYTES} bytes")


def _timing_summary(samples: list[int]) -> dict:
    ordered = sorted(samples)
    # Nearest-rank p95 for 1,000 samples: one-based rank 950.
    return {
        "median": (ordered[499] + ordered[500]) / 2,
        "p95": ordered[949],
    }


def aes_gcm_analysis(data: bytes) -> dict:
    """Measure 1,000 AES-256-GCM encryptions and decryptions in memory."""
    _check_data(data)
    key = _random_bytes(32)
    prefix = _random_bytes(4)
    nonces = [prefix + counter.to_bytes(8, "big") for counter in range(1020)]
    cipher = AESGCM(key)

    # Warm the API with 20 complete pairs, each on its own nonce.
    for nonce in nonces[:20]:
        sealed = cipher.encrypt(nonce, data, None)
        opened = cipher.decrypt(nonce, sealed, None)
        if opened != data:
            raise RuntimeError("AES-GCM warm-up round trip failed")

    encrypted: list[tuple[bytes, bytes]] = []
    encrypt_times: list[int] = []
    for nonce in nonces[20:]:
        started = _now_ns()
        sealed = cipher.encrypt(nonce, data, None)
        encrypt_times.append(_now_ns() - started)
        encrypted.append((nonce, sealed))

    decrypt_times: list[int] = []
    recovered: list[bytes] = []
    for nonce, sealed in encrypted:
        started = _now_ns()
        opened = cipher.decrypt(nonce, sealed, None)
        decrypt_times.append(_now_ns() - started)
        recovered.append(opened)

    plaintext_matches = all(item == data for item in recovered)
    if not plaintext_matches:
        raise RuntimeError("AES-GCM timed round trip failed")
    sample_nonce, sample_ciphertext = encrypted[0]
    return {
        "input_bytes": len(data),
        "warmup_pairs": 20,
        "timed_encryptions": 1000,
        "timed_decryptions": 1000,
        "ciphertext_bytes": len(sample_ciphertext),
        "tag_bytes": 16,
        "sample_nonce_hex": sample_nonce.hex(),
        "sample_ciphertext_hex": sample_ciphertext.hex(),
        "recovered_text": data.decode("utf-8", errors="replace"),
        "plaintext_matches": plaintext_matches,
        "encryption_timing_ns": _timing_summary(encrypt_times),
        "decryption_timing_ns": _timing_summary(decrypt_times),
    }


def _sweep_timing(samples: list[int], input_bytes: int) -> dict:
    """Report nearest-rank p95 and payload throughput from timed calls only."""
    ordered = sorted(samples)
    median_ns = statistics.median(ordered)
    p95_ns = ordered[math.ceil(0.95 * len(ordered)) - 1]
    return {
        "median_ns": median_ns,
        "p95_ns": p95_ns,
        "mib_per_s": (
            input_bytes * 1_000_000_000 / (median_ns * 1_048_576)
            if median_ns > 0 else 0.0
        ),
    }


def benchmark_size_sweep(
    *, sizes: tuple[int, ...] = SWEEP_SIZES, samples: int = 100,
) -> dict:
    """Measure five local crypto operations over a strictly bounded size grid."""
    if type(sizes) is not tuple:
        raise TypeError("sizes must be a tuple")
    if (
        not sizes or len(sizes) > len(SWEEP_SIZES)
        or any(type(size) is not int or size not in SWEEP_SIZES for size in sizes)
        or len(set(sizes)) != len(sizes)
    ):
        raise ValueError("sizes must be distinct approved byte sizes")
    if type(samples) is not int:
        raise TypeError("samples must be an integer")
    if not 1 <= samples <= 100:
        raise ValueError("samples must be between 1 and 100")

    aes = AESGCM(_random_bytes(32))
    signer = Ed25519PrivateKey.generate()
    verifier = signer.public_key()
    nonce_prefix = _random_bytes(4)
    nonce_counter = 0
    points = []
    for size in sizes:
        data = _random_bytes(size)
        expected_digest = hashlib.sha256(data).digest()

        # Warm every API at this size without reading the measurement clock.
        for _ in range(SWEEP_WARMUPS):
            nonce = nonce_prefix + nonce_counter.to_bytes(8, "big")
            nonce_counter += 1
            sealed = aes.encrypt(nonce, data, None)
            if aes.decrypt(nonce, sealed, None) != data:
                raise RuntimeError("AES-GCM sweep warm-up round trip failed")
            if hashlib.sha256(data).digest() != expected_digest:
                raise RuntimeError("SHA-256 sweep warm-up failed")
            signature = signer.sign(data)
            verifier.verify(signature, data)

        times = {name: [] for name in (
            "aes_encrypt", "aes_decrypt", "sha256", "ed25519_sign", "ed25519_verify"
        )}
        for _ in range(samples):
            nonce = nonce_prefix + nonce_counter.to_bytes(8, "big")
            nonce_counter += 1

            started = _now_ns()
            sealed = aes.encrypt(nonce, data, None)
            times["aes_encrypt"].append(_now_ns() - started)

            started = _now_ns()
            opened = aes.decrypt(nonce, sealed, None)
            times["aes_decrypt"].append(_now_ns() - started)
            if opened != data:
                raise RuntimeError("AES-GCM sweep timed round trip failed")

            started = _now_ns()
            digest = hashlib.sha256(data).digest()
            times["sha256"].append(_now_ns() - started)
            if digest != expected_digest:
                raise RuntimeError("SHA-256 sweep timed digest failed")

            started = _now_ns()
            signature = signer.sign(data)
            times["ed25519_sign"].append(_now_ns() - started)

            started = _now_ns()
            verifier.verify(signature, data)
            times["ed25519_verify"].append(_now_ns() - started)

        points.append({
            "input_bytes": size,
            **{name: _sweep_timing(values, size) for name, values in times.items()},
        })
    return {"sizes": list(sizes), "samples_per_size": samples, "points": points}


def _search_result(budget: int, search: Callable[[], tuple[int, dict]]) -> dict:
    start = _now_ns()
    attempts, found_values = search()
    elapsed = _now_ns() - start
    return {"budget": budget, "attempts": attempts, "elapsed_ns": elapsed, **found_values}


def sha256_analysis(data: bytes, *, candidate_limit: int = 10000) -> dict:
    """Show three bounded searches against the complete SHA-256 digest."""
    _check_data(data)
    if isinstance(candidate_limit, bool) or not isinstance(candidate_limit, int):
        raise TypeError("candidate_limit must be an integer")
    if not 1 <= candidate_limit <= 10000:
        raise ValueError("candidate_limit must be between 1 and 10000")

    target = _digest(data)

    def preimage_search() -> tuple[int, dict]:
        counter = 0
        hashed_attempts = 0
        while hashed_attempts < candidate_limit:
            candidate = b"sha256-preimage\x00" + counter.to_bytes(8, "big") + _random_bytes(32)
            counter += 1
            if candidate == data:
                continue
            hashed_attempts += 1
            if _digest(candidate) == target:
                return hashed_attempts, {"found": True, "candidate_hex": candidate.hex()}
        return hashed_attempts, {"found": False, "candidate_hex": None}

    def second_preimage_search() -> tuple[int, dict]:
        for attempt in range(candidate_limit):
            candidate = data + b"\x00sha256-second-preimage\x00" + attempt.to_bytes(8, "big")
            if _digest(candidate) == target:
                return attempt + 1, {"found": True, "candidate_hex": candidate.hex()}
        return candidate_limit, {"found": False, "candidate_hex": None}

    def collision_search() -> tuple[int, dict]:
        seen: dict[bytes, bytes] = {}
        for attempt in range(candidate_limit):
            candidate = b"sha256-collision\x00" + attempt.to_bytes(8, "big") + _random_bytes(32)
            candidate_digest = _digest(candidate)
            previous = seen.get(candidate_digest)
            if previous is not None and previous != candidate:
                return attempt + 1, {
                    "found": True,
                    "first_candidate_hex": previous.hex(),
                    "second_candidate_hex": candidate.hex(),
                    "digest_hex": candidate_digest.hex(),
                }
            seen[candidate_digest] = candidate
        return candidate_limit, {
            "found": False,
            "first_candidate_hex": None,
            "second_candidate_hex": None,
            "digest_hex": None,
        }

    return {
        "input_bytes": len(data),
        "target_digest_hex": target.hex(),
        "preimage": _search_result(candidate_limit, preimage_search),
        "second_preimage": _search_result(candidate_limit, second_preimage_search),
        "collision": _search_result(candidate_limit, collision_search),
    }


def _aes_block_encryptor(key: bytes) -> Callable[[bytes], bytes]:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()

    def encrypt(block: bytes) -> bytes:
        return encryptor.update(block)

    return encrypt


def _hamming_bits(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def _avalanche_summary(changed_counts: list[int]) -> dict:
    percentages = [count * 100.0 / 128 for count in changed_counts]
    distribution = [
        {"lower_percent": index * 10, "upper_percent": (index + 1) * 10, "count": 0}
        for index in range(10)
    ]
    for count in changed_counts:
        # Integer arithmetic keeps the half-open boundaries exact; 128 bits
        # (100%) belongs to the inclusive final bin.
        distribution[min(count * 10 // 128, 9)]["count"] += 1
    return {
        "mean_changed_bits": statistics.fmean(changed_counts),
        "min_changed_bits": min(changed_counts),
        "max_changed_bits": max(changed_counts),
        "mean_changed_percent": statistics.fmean(percentages),
        "min_changed_percent": min(percentages),
        "max_changed_percent": max(percentages),
        "distribution_10pct": distribution,
    }


def aes_primitive_analysis(data: bytes) -> dict:
    """Measure single-block AES-256 plaintext and key bit-flip effects."""
    _check_data(data)
    block = data[:16].ljust(16, b"\x00")
    plaintext_changes: list[int] = []
    key_changes: list[int] = []
    sac_counts = [[0 for _ in range(128)] for _ in range(128)]
    hex_character_change = None

    for key_index in range(32):
        key = _random_bytes(32)
        encrypt = _aes_block_encryptor(key)
        baseline = encrypt(block)

        for input_bit in range(128):
            altered = bytearray(block)
            altered[input_bit // 8] ^= 1 << (7 - input_bit % 8)
            output = encrypt(bytes(altered))
            if key_index == 0 and input_bit == 0:
                changed_characters = sum(
                    left != right for left, right in zip(baseline.hex(), output.hex())
                )
                hex_character_change = {
                    "changed": changed_characters,
                    "total": 32,
                    "percent": changed_characters * 100.0 / 32,
                }
            changed = _hamming_bits(baseline, output)
            plaintext_changes.append(changed)
            for output_bit in range(128):
                if (baseline[output_bit // 8] ^ output[output_bit // 8]) & (1 << (7 - output_bit % 8)):
                    sac_counts[input_bit][output_bit] += 1

        for key_bit in range(256):
            altered_key = bytearray(key)
            altered_key[key_bit // 8] ^= 1 << (7 - key_bit % 8)
            output = _aes_block_encryptor(bytes(altered_key))(block)
            key_changes.append(_hamming_bits(baseline, output))

    flip_percentages = [
        [count * 100.0 / 32 for count in row]
        for row in sac_counts
    ]
    deviations = [abs(value - 50.0) for row in flip_percentages for value in row]
    all_percentages = [value for row in flip_percentages for value in row]
    summary_16x16 = [
        [
            statistics.fmean(
                flip_percentages[input_bit][output_bit]
                for input_bit in range(row * 8, row * 8 + 8)
                for output_bit in range(column * 8, column * 8 + 8)
            )
            for column in range(16)
        ]
        for row in range(16)
    ]
    return {
        "input_bytes": len(data),
        "block_hex": block.hex(),
        "keys_tested": 32,
        "baseline_encryptions": 32,
        "plaintext_comparisons": 4096,
        "key_comparisons": 8192,
        "total_encryptions": 12320,
        "plaintext_avalanche": _avalanche_summary(plaintext_changes),
        "key_avalanche": _avalanche_summary(key_changes),
        "hex_character_change": hex_character_change,
        "sac": {
            "flip_percentages": flip_percentages,
            "summary_16x16": summary_16x16,
            "mean_abs_deviation_percentage_points": statistics.fmean(deviations),
            "min_flip_percent": min(all_percentages),
            "max_flip_percent": max(all_percentages),
        },
    }
