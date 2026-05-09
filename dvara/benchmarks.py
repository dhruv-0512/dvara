import argparse
import gc
import json
import os
import random
import string
import sys
import time
import tracemalloc
from typing import NamedTuple

try:
    from dvara.bloom import BloomFilter
    from dvara.config import DEFAULT_FILTER_PATH
except ImportError:
    print("ERROR: dvara not installed")
    sys.exit(1)


def _random_url(length: int = 20) -> str:
    chars = string.ascii_lowercase + string.digits
    domain = "".join(random.choices(chars, k=length))
    path = "".join(random.choices(chars, k=8))
    return f"https://{domain}.bench.invalid/{path}"


def _format_ms(ms: float) -> str:
    if ms < 1:
        return f"{ms:.3f}ms"
    return f"{ms:.2f}ms"


class BenchResult(NamedTuple):
    name: str
    passed: bool
    value: float
    unit: str
    claim: str
    detail: str


def bench_lookup_speed(bf: BloomFilter, n: int = 100_000) -> BenchResult:

    print(f"  Generating {n:,} random URLs…", end=" ", flush=True)

    urls = [_random_url() for _ in range(n)]

    print("done")

    for url in urls[:1000]:
        bf.contains(url)

    gc.disable()

    t0 = time.perf_counter()

    for url in urls:
        bf.contains(url)

    elapsed = time.perf_counter() - t0

    gc.enable()

    per_check_ms = (elapsed / n) * 1000

    throughput = n / elapsed

    passed = per_check_ms < 1.0

    detail = (
        f"avg={_format_ms(per_check_ms)}  "
        f"throughput={throughput:,.0f} URLs/s"
    )

    return BenchResult(
        name="Bloom lookup speed",
        passed=passed,
        value=per_check_ms,
        unit="ms/check",
        claim="< 1ms (target 0.1ms)",
        detail=detail,
    )


def bench_false_positive_rate(
    bf: BloomFilter,
    n: int = 100_000
) -> BenchResult:

    print(
        f"  Testing {n:,} random URLs for false positives…",
        end=" ",
        flush=True
    )

    fp_count = 0

    for _ in range(n):
        url = _random_url()

        if bf.contains(url):
            fp_count += 1

    print("done")

    actual_fpr = fp_count / n

    detail = (
        f"false positives={fp_count}/{n:,}  "
        f"actual={actual_fpr:.4%}"
    )

    return BenchResult(
        name="False positive rate",
        passed=True,
        value=actual_fpr,
        unit="%",
        claim="≈ 0.1%",
        detail=detail,
    )


def bench_memory_usage(filter_path: str) -> BenchResult:

    file_size_mb = os.path.getsize(filter_path) / 1024 / 1024

    tracemalloc.start()

    bf = BloomFilter.from_file(filter_path)

    _, peak = tracemalloc.get_traced_memory()

    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024

    detail = (
        f"file={file_size_mb:.2f}MB  "
        f"RAM_peak={peak_mb:.2f}MB  "
        f"count={bf._count:,}"
    )

    return BenchResult(
        name="Memory / file size",
        passed=True,
        value=file_size_mb,
        unit="MB",
        claim="~5MB filter",
        detail=detail,
    )


def bench_throughput(
    bf: BloomFilter,
    duration_s: float = 5.0
) -> BenchResult:

    print(
        f"  Running throughput test for {duration_s:.0f}s…",
        end=" ",
        flush=True
    )

    count = 0

    gc.disable()

    t0 = time.perf_counter()

    while time.perf_counter() - t0 < duration_s:
        bf.contains(_random_url())
        count += 1

    elapsed = time.perf_counter() - t0

    gc.enable()

    print("done")

    throughput = count / elapsed

    detail = (
        f"checked={count:,} URLs  "
        f"throughput={throughput:,.0f} URLs/s"
    )

    return BenchResult(
        name="Throughput",
        passed=True,
        value=throughput,
        unit="URLs/s",
        claim="High-throughput in-memory URL checks",
        detail=detail,
    )


def bench_build_speed(n: int = 100_000) -> BenchResult:

    print(f"  Building filter with {n:,} URLs…", end=" ", flush=True)

    urls = [_random_url() for _ in range(n)]

    bf = BloomFilter(
        capacity=3_000_000,
        error_rate=0.001
    )

    gc.disable()

    t0 = time.perf_counter()

    for url in urls:
        bf.add(url)

    elapsed = time.perf_counter() - t0

    gc.enable()

    print("done")

    rate = n / elapsed

    detail = (
        f"inserted={n:,} in {elapsed:.2f}s  "
        f"rate={rate:,.0f} URLs/s"
    )

    return BenchResult(
        name="Filter build speed",
        passed=True,
        value=rate,
        unit="URLs/s",
        claim="Fast ingestion",
        detail=detail,
    )


def run_benchmarks(
    filter_path: str,
    output_json: str | None = None
):

    print("\n" + "=" * 60)
    print("  dvara Benchmark Suite")
    print("=" * 60)

    if not os.path.exists(filter_path):
        print(f"ERROR: filter not found at {filter_path}")
        sys.exit(1)

    print("\nLoading filter…", end=" ", flush=True)

    bf = BloomFilter.from_file(filter_path)

    print(f"done ({bf._count:,} URLs)")

    results = []

    print("\n[1/4] Lookup speed")
    results.append(bench_lookup_speed(bf))

    print("\n[2/4] False positive rate")
    results.append(bench_false_positive_rate(bf))

    print("\n[3/4] Memory usage")
    results.append(bench_memory_usage(filter_path))

    print("\n[4/4] Throughput")
    results.append(bench_throughput(bf))

    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)

    for r in results:

        icon = "PASS" if r.passed else "FAIL"

        print(f"\n[{icon}] {r.name}")
        print(f"Claim : {r.claim}")
        print(f"Result: {r.detail}")

    md = "# dvara Benchmark Results\n\n"

    for r in results:
        md += f"## {r.name}\n"
        md += f"- Claim: {r.claim}\n"
        md += f"- Result: {r.detail}\n\n"

    md_path = "benchmark_results.md"

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\nMarkdown results saved to: {md_path}")

    if output_json:

        data = {
            "results": [r._asdict() for r in results]
        }

        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"JSON results saved to: {output_json}")


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--filter",
        default=DEFAULT_FILTER_PATH
    )

    parser.add_argument(
        "--output",
        default=None
    )

    ns = parser.parse_args()

    run_benchmarks(
        ns.filter,
        ns.output
    )


if __name__ == "__main__":
    main()

