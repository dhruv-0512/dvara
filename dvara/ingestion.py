"""
dvara/ingestion.py

Pulls malicious URLs from three threat feeds:
  - URLhaus  (CSV)
  - PhishTank (JSON)
  - OpenPhish (plaintext)

Normalises, deduplicates, builds a BloomFilter, and saves it to disk.
Also writes a PostgreSQL-ready CSV of confirmed URLs for the DB seed.

Usage:
    python -m dvara.ingestion
    python -m dvara.ingestion --output ~/.dvara/filter.bin
"""

import argparse
import csv
import gzip
import io
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from dvara.bloom import BloomFilter

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Feed URLs
# ------------------------------------------------------------------

URLHAUS_CSV_URL   = "https://urlhaus.abuse.ch/downloads/csv_recent/"
PHISHTANK_JSON_URL = (
    "http://data.phishtank.com/data/online-valid.json.gz"
)
OPENPHISH_TXT_URL = "https://openphish.com/feed.txt"

REQUEST_TIMEOUT   = 30   # seconds per HTTP request
REQUEST_HEADERS   = {"User-Agent": "dvara-ingestion/1.0 (github.com/dvara)"}

# ------------------------------------------------------------------
# Bloom filter settings  (matches production spec)
# ------------------------------------------------------------------

BLOOM_CAPACITY  = 3_000_000
BLOOM_FPR       = 0.001      # 0.1%

# ------------------------------------------------------------------
# Fetchers — one per feed
# ------------------------------------------------------------------


def fetch_urlhaus() -> set[str]:
    """
    URLhaus publishes a CSV of recent malicious URLs.
    Lines starting with '#' are comments.
    Column layout: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    log.info("Fetching URLhaus …")
    urls: set[str] = set()

    try:
        resp = requests.get(URLHAUS_CSV_URL, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        resp.raise_for_status()
    except requests.RequestException as e:
        log.warning("URLhaus fetch failed: %s", e)
        return urls

    reader = csv.reader(
        line for line in resp.text.splitlines() if not line.startswith("#")
    )
    for row in reader:
        if len(row) >= 3:
            url = row[2].strip()
            if url:
                urls.add(url)

    log.info("URLhaus: %d URLs", len(urls))
    return urls


def fetch_phishtank() -> set[str]:
    """
    PhishTank publishes a gzipped JSON file of verified phishing URLs.
    Each entry has a 'url' key.
    Note: requires free API key for high-volume use; works without for ingestion.
    """
    log.info("Fetching PhishTank …")
    urls: set[str] = set()

    try:
        resp = requests.get(PHISHTANK_JSON_URL, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        resp.raise_for_status()
    except requests.RequestException as e:
        log.warning("PhishTank fetch failed: %s", e)
        return urls

    try:
        with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
            data = json.load(gz)
        for entry in data:
            url = entry.get("url", "").strip()
            if url:
                urls.add(url)
    except Exception as e:
        log.warning("PhishTank parse failed: %s", e)

    log.info("PhishTank: %d URLs", len(urls))
    return urls


def fetch_openphish() -> set[str]:
    """
    OpenPhish publishes a plain-text feed — one URL per line.
    Free tier is updated every 12 hours.
    """
    log.info("Fetching OpenPhish …")
    urls: set[str] = set()

    try:
        resp = requests.get(OPENPHISH_TXT_URL, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        resp.raise_for_status()
    except requests.RequestException as e:
        log.warning("OpenPhish fetch failed: %s", e)
        return urls

    for line in resp.text.splitlines():
        url = line.strip()
        if url:
            urls.add(url)

    log.info("OpenPhish: %d URLs", len(urls))
    return urls


# ------------------------------------------------------------------
# Normalisation
# ------------------------------------------------------------------


def normalise(url: str) -> str | None:
    """
    Normalise a URL so duplicates across feeds are collapsed.

    Steps:
      1. Strip whitespace
      2. Lowercase scheme and host
      3. Drop trailing slash on bare paths
      4. Drop fragment (#section)
      5. Reject obviously malformed entries

    Returns None if the URL should be discarded.
    """
    url = url.strip()
    if not url:
        return None

    try:
        parsed = urlparse(url)
    except Exception:
        return None

    # Must have a recognised scheme
    if parsed.scheme not in ("http", "https", "ftp"):
        return None

    # Must have a non-empty host
    if not parsed.netloc:
        return None

    # Reconstruct with lowercased scheme + host, drop fragment
    normalised = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
    ).geturl()

    # Strip trailing slash on root paths  (http://evil.com/ → http://evil.com)
    if normalised.endswith("/") and parsed.path in ("", "/"):
        normalised = normalised.rstrip("/")

    return normalised


# ------------------------------------------------------------------
# Core pipeline
# ------------------------------------------------------------------


def build_filter(
    output_path: str,
    confirmed_csv_path: str | None = None,
) -> BloomFilter:
    """
    Full ingestion pipeline:
      1. Fetch all three feeds (failures are logged but non-fatal)
      2. Normalise and deduplicate
      3. Build BloomFilter
      4. Save filter binary to output_path
      5. Optionally write confirmed-URLs CSV for PostgreSQL seeding

    Returns the built BloomFilter.
    """
    start = time.perf_counter()

    # ---- Fetch ----
    raw: set[str] = set()
    raw |= fetch_urlhaus()
    raw |= fetch_phishtank()
    raw |= fetch_openphish()
    log.info("Total raw URLs (union): %d", len(raw))

    # ---- Normalise ----
    clean: set[str] = set()
    discarded = 0
    for url in raw:
        n = normalise(url)
        if n:
            clean.add(n)
        else:
            discarded += 1

    log.info("After normalisation: %d URLs (%d discarded)", len(clean), discarded)

    # ---- Build filter ----
    log.info(
        "Building BloomFilter (capacity=%d, fpr=%.3f%%) …",
        BLOOM_CAPACITY,
        BLOOM_FPR * 100,
    )
    bf = BloomFilter(capacity=BLOOM_CAPACITY, error_rate=BLOOM_FPR)
    for url in clean:
        bf.add(url)

    log.info("Filter built: %s", bf)

    # ---- Save filter binary ----
    os.makedirs(os.path.dirname(output_path), exist_ok=True) if os.path.dirname(output_path) else None
    bf.to_file(output_path)
    size_kb = os.path.getsize(output_path) / 1024
    log.info("Filter saved → %s (%.1f KB)", output_path, size_kb)

    # ---- Optional: write confirmed-URLs CSV ----
    if confirmed_csv_path:
        _write_confirmed_csv(clean, confirmed_csv_path)

    elapsed = time.perf_counter() - start
    log.info("Ingestion complete in %.1fs", elapsed)
    return bf


def _write_confirmed_csv(urls: set[str], path: str) -> None:
    """
    Write a CSV suitable for bulk-loading into PostgreSQL confirmed_urls table.

    Columns: url, ingested_at
    """
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    now = datetime.now(timezone.utc).isoformat()
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "ingested_at"])
        for url in sorted(urls):
            writer.writerow([url, now])
    log.info("Confirmed URLs CSV saved → %s (%d rows)", path, len(urls))


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="dvara ingestion — fetch threat feeds and build bloom filter"
    )
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.expanduser("~"), ".dvara", "filter.bin"),
        help="Path to write the bloom filter binary (default: ~/.dvara/filter.bin)",
    )
    parser.add_argument(
        "--confirmed-csv",
        default=None,
        metavar="PATH",
        help="Optional path to write confirmed URLs CSV for PostgreSQL seeding",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and normalise URLs but do not write any files",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    if args.dry_run:
        log.info("Dry run — no files will be written")
        raw: set[str] = set()
        raw |= fetch_urlhaus()
        raw |= fetch_phishtank()
        raw |= fetch_openphish()
        clean = {n for url in raw if (n := normalise(url))}
        log.info("Dry run complete. Would ingest %d URLs.", len(clean))
        return

    build_filter(
        output_path=args.output,
        confirmed_csv_path=args.confirmed_csv,
    )


if __name__ == "__main__":
    main()
