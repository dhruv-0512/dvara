"""
tests/test_bloom.py

Test suite for dvara BloomFilter.
Verifies:
  - Basic add / contains behaviour
  - Zero false negatives (mathematical guarantee)
  - FPR stays within 20% of theoretical at 3M URLs
  - save / load round-trip preserves filter state
  - Edge cases and bad inputs
"""

import os
import tempfile
import pytest
from dvara.bloom import BloomFilter


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_urls(prefix: str, count: int) -> list[str]:
    """Generate a list of unique URLs like https://prefix-0.com … prefix-n.com"""
    return [f"https://{prefix}-{i}.com" for i in range(count)]


# ------------------------------------------------------------------
# Basic behaviour
# ------------------------------------------------------------------

class TestBasicBehaviour:

    def test_contains_after_add(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        bf.add("https://evil.com")
        assert bf.contains("https://evil.com")

    def test_dunder_contains(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        bf.add("https://phish.net")
        assert "https://phish.net" in bf

    def test_not_added_returns_false(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        # With high probability a random URL not added is not found
        assert not bf.contains("https://definitely-not-added-xyzzy.com")

    def test_count_increments(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        assert bf._count == 0
        bf.add("https://a.com")
        bf.add("https://b.com")
        assert bf._count == 2

    def test_fill_ratio_increases(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        ratio_before = bf.fill_ratio
        for url in _make_urls("site", 100):
            bf.add(url)
        assert bf.fill_ratio > ratio_before


# ------------------------------------------------------------------
# Zero false negatives — the hard guarantee
# ------------------------------------------------------------------

class TestZeroFalseNegatives:

    def test_no_false_negatives_small(self):
        """Every URL that was added must always be found."""
        bf = BloomFilter(capacity=10_000, error_rate=0.001)
        urls = _make_urls("malicious", 5_000)
        for url in urls:
            bf.add(url)
        false_negatives = [url for url in urls if not bf.contains(url)]
        assert false_negatives == [], (
            f"False negatives found: {false_negatives[:5]}"
        )

    def test_no_false_negatives_at_capacity(self):
        """No false negatives even when filter is filled to capacity."""
        n = 50_000
        bf = BloomFilter(capacity=n, error_rate=0.001)
        urls = _make_urls("threat", n)
        for url in urls:
            bf.add(url)
        false_negatives = sum(1 for url in urls if not bf.contains(url))
        assert false_negatives == 0, f"{false_negatives} false negatives at capacity"


# ------------------------------------------------------------------
# False positive rate — must stay within 20% of theoretical
# ------------------------------------------------------------------

class TestFalsePositiveRate:

    def test_fpr_within_tolerance_medium(self):
        """
        At 50k URLs and 1% target FPR, measured FPR must be <= 1.2%
        (theoretical + 20% tolerance).
        """
        n = 50_000
        target_fpr = 0.01
        bf = BloomFilter(capacity=n, error_rate=target_fpr)

        # Fill the filter
        for url in _make_urls("known-bad", n):
            bf.add(url)

        # Test with URLs definitely not in the filter
        test_urls = _make_urls("clean-site", 10_000)
        false_positives = sum(1 for url in test_urls if bf.contains(url))
        measured_fpr = false_positives / len(test_urls)

        max_allowed_fpr = target_fpr * 1.20   # 20% tolerance
        assert measured_fpr <= max_allowed_fpr, (
            f"FPR too high: measured={measured_fpr:.4%}, "
            f"target={target_fpr:.4%}, allowed<={max_allowed_fpr:.4%}"
        )

    def test_fpr_within_tolerance_large(self):
        """
        At 200k URLs and 0.1% target FPR, measured FPR must be <= 0.12%.
        This is a scaled-down proxy for the 3M URL production scenario.
        """
        n = 200_000
        target_fpr = 0.001
        bf = BloomFilter(capacity=n, error_rate=target_fpr)

        for url in _make_urls("malware", n):
            bf.add(url)

        test_urls = _make_urls("safe", 10_000)
        false_positives = sum(1 for url in test_urls if bf.contains(url))
        measured_fpr = false_positives / len(test_urls)

        max_allowed_fpr = target_fpr * 1.20
        assert measured_fpr <= max_allowed_fpr, (
            f"FPR too high: measured={measured_fpr:.4%}, "
            f"target={target_fpr:.4%}, allowed<={max_allowed_fpr:.4%}"
        )


# ------------------------------------------------------------------
# Serialisation — save / load round-trip
# ------------------------------------------------------------------

class TestSerialisation:

    def test_roundtrip_preserves_members(self):
        """URLs added before save must still be found after load."""
        bf = BloomFilter(capacity=10_000, error_rate=0.001)
        urls = _make_urls("persist", 1_000)
        for url in urls:
            bf.add(url)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            bf.to_file(path)
            bf2 = BloomFilter.from_file(path)

            false_negatives = [url for url in urls if not bf2.contains(url)]
            assert false_negatives == [], (
                f"URLs lost after reload: {false_negatives[:5]}"
            )
        finally:
            os.unlink(path)

    def test_roundtrip_preserves_metadata(self):
        """capacity, m, k, error_rate, count must survive save/load."""
        bf = BloomFilter(capacity=5_000, error_rate=0.005)
        for url in _make_urls("meta", 500):
            bf.add(url)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            bf.to_file(path)
            bf2 = BloomFilter.from_file(path)

            assert bf2.capacity == bf.capacity
            assert bf2.m == bf.m
            assert bf2.k == bf.k
            assert abs(bf2.error_rate - bf.error_rate) < 1e-10
            assert bf2._count == bf._count
        finally:
            os.unlink(path)

    def test_roundtrip_bit_array_length(self):
        """Bit array length must be exactly m after loading (no padding bits)."""
        bf = BloomFilter(capacity=1_000, error_rate=0.01)

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name

        try:
            bf.to_file(path)
            bf2 = BloomFilter.from_file(path)
            assert len(bf2._bits) == bf2.m
        finally:
            os.unlink(path)


# ------------------------------------------------------------------
# Optimal parameter calculation
# ------------------------------------------------------------------

class TestOptimalParameters:

    def test_production_size(self):
        """3M URLs at 0.1% FPR should produce ~5.2MB and k=10."""
        bf = BloomFilter(capacity=3_000_000, error_rate=0.001)
        size_mb = bf.m / 8 / 1024 / 1024
        assert 5.0 <= size_mb <= 5.5, f"Expected ~5.2MB, got {size_mb:.2f}MB"
        assert bf.k == 10, f"Expected k=10, got k={bf.k}"

    def test_higher_fpr_smaller_filter(self):
        """Relaxing FPR from 0.1% to 1% should shrink the filter."""
        bf_tight = BloomFilter(capacity=100_000, error_rate=0.001)
        bf_loose = BloomFilter(capacity=100_000, error_rate=0.01)
        assert bf_loose.m < bf_tight.m

    def test_k_at_least_1(self):
        """k must always be at least 1 regardless of inputs."""
        bf = BloomFilter(capacity=1, error_rate=0.5)
        assert bf.k >= 1


# ------------------------------------------------------------------
# Edge cases and bad inputs
# ------------------------------------------------------------------

class TestEdgeCases:

    def test_invalid_capacity_zero(self):
        with pytest.raises(ValueError, match="capacity"):
            BloomFilter(capacity=0, error_rate=0.01)

    def test_invalid_capacity_negative(self):
        with pytest.raises(ValueError, match="capacity"):
            BloomFilter(capacity=-1, error_rate=0.01)

    def test_invalid_error_rate_zero(self):
        with pytest.raises(ValueError, match="error_rate"):
            BloomFilter(capacity=1000, error_rate=0.0)

    def test_invalid_error_rate_one(self):
        with pytest.raises(ValueError, match="error_rate"):
            BloomFilter(capacity=1000, error_rate=1.0)

    def test_invalid_error_rate_above_one(self):
        with pytest.raises(ValueError, match="error_rate"):
            BloomFilter(capacity=1000, error_rate=1.5)

    def test_unicode_urls(self):
        """Filter must handle unicode URLs without crashing."""
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        url = "https://münchen-phishing.de/злой"
        bf.add(url)
        assert bf.contains(url)

    def test_empty_string(self):
        """Empty string is a valid (if odd) URL — should not crash."""
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        bf.add("")
        assert bf.contains("")

    def test_repr_is_string(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        assert isinstance(repr(bf), str)
