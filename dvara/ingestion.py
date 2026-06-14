"""
dvara/ingestion.py

Threat feed ingestion pipeline for dvara.

Feeds (total ~2M+ URLs):
    URLhaus full archive   — ~1.5M malware URLs
    URLhaus recent         — ~26k  recent additions
    PhishTank              — ~50-80k phishing URLs
    OpenPhish              — ~500   phishing URLs
    PhishStats             — ~100k  phishing URLs with scores
    Cert.pl                — ~500k  malicious domains

Flow:
    download feeds → normalize → deduplicate → build bloom filter → save
"""
import zipfile
import argparse
import csv
import gzip
import io
import json
import logging
import os
import sys
import time
from typing import Iterator
from urllib.parse import urlparse, urlunparse

import requests

from dvara.bloom import BloomFilter
from dvara.config import DEFAULT_FILTER_PATH

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ------------------------------------------------------------------
# Feed definitions
# ------------------------------------------------------------------

FEEDS = {
    "urlhaus_recent": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "format": "urlhaus_csv",
        "description": "URLhaus recent (~26k URLs)",
    },
    "urlhaus_full": {
        "url": "https://urlhaus.abuse.ch/downloads/csv/",
        "format": "urlhaus_csv",
        "description": "URLhaus full archive (~1.5M URLs)",
    },
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json.gz",
        "format": "phishtank_json",
        "description": "PhishTank verified phishing (~50-80k URLs)",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "format": "plaintext",
        "description": "OpenPhish feed (~500 URLs)",
    },
    "phishstats": {
        "url": "https://phishstats.info/phish_score.csv",
        "format": "phishstats_csv",
        "description": "PhishStats (~100k URLs)",
    },
    "certpl": {
        "url": "https://hole.cert.pl/domains/domains.txt",
        "format": "plaintext_domains",
        "description": "Cert.pl malicious domains (~500k)",
    },
}

# ------------------------------------------------------------------
# Normalization
# ------------------------------------------------------------------

REMOVE_WWW     = True
LOWERCASE      = True
STRIP_FRAGMENT = True
DEFAULT_PORTS  = {80: "http", 443: "https"}


def normalize_url(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    if raw.startswith("//"):
        raw = "https:" + raw
    elif not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        p = urlparse(raw)
        scheme = p.scheme.lower()
        if scheme not in ("http", "https"):
            return None

        host = p.hostname
        if not host:
            return None
        host = host.lower()

        if REMOVE_WWW and host.startswith("www."):
            host = host[4:]

        try:
            port = p.port  # this is what was crashing
        except ValueError:
            return None    # garbage port — skip URL

        if port and DEFAULT_PORTS.get(port) == scheme:
            port = None

        netloc = host if port is None else f"{host}:{port}"
        path = p.path or "/"
        if path == "/":
            path = ""

        normalized = urlunparse((scheme, netloc, path, p.params, p.query, ""))
        return normalized

    except Exception:
        return None


# ------------------------------------------------------------------
# Feed parsers
# ------------------------------------------------------------------

def _parse_phishtank_json(content: bytes) -> Iterator[str]:
    """Parse PhishTank gzipped JSON."""
    try:
        with gzip.open(io.BytesIO(content)) as f:
            data = json.load(f)
        for entry in data:
            url = entry.get("url", "").strip()
            if url:
                yield url
    except Exception as e:
        log.warning("PhishTank parse error: %s", e)


def _parse_plaintext(content: str) -> Iterator[str]:
    """Parse plain URL list (one URL per line)."""
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def _parse_plaintext_domains(content: str) -> Iterator[str]:
    """Parse plain domain list — convert to https:// URLs."""
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # These are bare domains — treat as https
            yield f"https://{line}"


def _parse_urlhaus_csv(content: bytes) -> Iterator[str]:
    """Parse URLhaus ZIP-compressed CSV."""

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # Usually csv.txt
            name = zf.namelist()[0]

            with zf.open(name) as f:
                text = f.read().decode("utf-8", errors="ignore")

    except Exception as e:
        log.warning("URLHaus ZIP parse error: %s", e)
        return

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    reader = csv.reader(io.StringIO(text))

    for row in reader:
        if not row:
            continue

        if row[0].startswith("#"):
            continue

        # id,dateadded,url,...
        if len(row) >= 3:
            url = row[2].strip().strip('"')

            if url:
                yield url


PARSERS = {
    "urlhaus_csv": _parse_urlhaus_csv,
    "phishtank_json":   lambda c: _parse_phishtank_json(c),
    "plaintext":        lambda c: _parse_plaintext(c.decode("utf-8", errors="ignore")),
    "plaintext_domains": lambda c: _parse_plaintext_domains(c.decode("utf-8", errors="ignore")),
    "phishstats_csv":   lambda c: _parse_phishstats_csv(c.decode("utf-8", errors="ignore")),
}


# ------------------------------------------------------------------
# Ingestion pipeline
# ------------------------------------------------------------------

def fetch_feed(name: str, feed: dict, timeout: int = 60) -> bytes | None:
    """Download a single feed. Returns raw bytes or None on failure."""
    log.info("Fetching %s (%s)…", name, feed["description"])
    try:
        resp = requests.get(
            feed["url"],
            timeout=timeout,
            headers={"User-Agent": "dvara-ingestion/1.0"},
        )
        resp.raise_for_status()
        log.info("  → %d bytes", len(resp.content))
        return resp.content
    except Exception as e:
        log.warning("  ✗ Failed to fetch %s: %s", name, e)
        return None


def ingest_feeds(
    feeds: list[str] | None = None,
    capacity: int = 3_000_000,
    error_rate: float = 0.001,
    dry_run: bool = False,
    output_path: str = DEFAULT_FILTER_PATH,
) -> dict:
    """
    Main ingestion pipeline.

    Args:
        feeds:       list of feed names to ingest (None = all)
        capacity:    bloom filter capacity
        error_rate:  target false positive rate
        dry_run:     if True, fetch and count but don't write filter
        output_path: where to save the filter binary

    Returns:
        dict with stats: total_raw, total_normalized, total_dupes, per_feed counts
    """
    selected = {k: v for k, v in FEEDS.items() if feeds is None or k in feeds}
    if not selected:
        raise ValueError(f"No valid feeds selected. Available: {list(FEEDS.keys())}")

    log.info("Starting ingestion: %d feeds, capacity=%d, FPR=%.3f%%",
             len(selected), capacity, error_rate * 100)

    # Collect all normalized URLs (deduplicated)
    seen: set[str] = set()
    stats = {
        "feeds": {},
        "total_raw": 0,
        "total_normalized": 0,
        "total_dupes": 0,
    }

    t_start = time.perf_counter()

    for name, feed in selected.items():
        content = fetch_feed(name, feed)
        if content is None:
            stats["feeds"][name] = {"status": "failed", "raw": 0, "added": 0}
            continue

        parser = PARSERS.get(feed["format"])
        if parser is None:
            log.warning("No parser for format: %s", feed["format"])
            continue

        raw_count   = 0
        added_count = 0
        dupe_count  = 0

        for raw_url in parser(content):
            raw_count += 1
            normalized = normalize_url(raw_url)
            if normalized is None:
                continue
            if normalized in seen:
                dupe_count += 1
                continue
            seen.add(normalized)
            added_count += 1

        stats["feeds"][name] = {
            "status": "ok",
            "raw": raw_count,
            "added": added_count,
            "dupes": dupe_count,
        }
        stats["total_raw"]        += raw_count
        stats["total_normalized"] += added_count
        stats["total_dupes"]      += dupe_count

        log.info("  %s: %d raw → %d unique (%d dupes)", name, raw_count, added_count, dupe_count)

    total_unique = len(seen)
    stats["total_unique"] = total_unique
    log.info("Total unique URLs: %d", total_unique)

    if dry_run:
        log.info("Dry run — skipping filter build")
        stats["dry_run"] = True
        return stats

    # Build bloom filter
    log.info("Building bloom filter (capacity=%d, FPR=%.4f)…", capacity, error_rate)
    bf = BloomFilter(capacity=capacity, error_rate=error_rate)
    for url in seen:
        bf.add(url)

    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True) if os.path.dirname(output_path) else None
    bf.to_file(output_path)
    size_mb = os.path.getsize(output_path) / 1024 / 1024

    elapsed = time.perf_counter() - t_start
    log.info("Filter saved to %s (%.2f MB) in %.1fs", output_path, size_mb, elapsed)
    log.info("Fill ratio: %.4f%%  |  Actual FPR: %.6f%%",
             bf.fill_ratio * 100, bf.actual_fpr * 100)

    stats.update({
        "filter_path":  output_path,
        "filter_mb":    round(size_mb, 2),
        "fill_ratio":   bf.fill_ratio,
        "actual_fpr":   bf.actual_fpr,
        "elapsed_s":    round(elapsed, 1),
    })
    return stats


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main(args: list[str] | None = None):
    parser = argparse.ArgumentParser(description="dvara ingestion pipeline")
    parser.add_argument("--output",   default=DEFAULT_FILTER_PATH, help="Output filter path")
    parser.add_argument("--capacity", type=int,   default=3_000_000, help="Bloom filter capacity")
    parser.add_argument("--fpr",      type=float, default=0.001,     help="Target false positive rate")
    parser.add_argument("--feeds",    nargs="+",  default=None,
                        choices=list(FEEDS.keys()),
                        help="Feeds to ingest (default: all)")
    parser.add_argument("--dry-run",  action="store_true", help="Fetch but don't write filter")
    parser.add_argument("--list-feeds", action="store_true", help="List available feeds and exit")
    ns = parser.parse_args(args)

    if ns.list_feeds:
        print("\nAvailable feeds:")
        for name, feed in FEEDS.items():
            print(f"  {name:<20} {feed['description']}")
        print()
        sys.exit(0)

    stats = ingest_feeds(
        feeds=ns.feeds,
        capacity=ns.capacity,
        error_rate=ns.fpr,
        dry_run=ns.dry_run,
        output_path=ns.output,
    )

    print("\n── Ingestion Summary ──")
    for name, fstats in stats["feeds"].items():
        status = "✅" if fstats["status"] == "ok" else "✗"
        if fstats["status"] == "ok":
            print(f"  {status} {name:<20} {fstats['added']:>8,} URLs  ({fstats['raw']:,} raw, {fstats['dupes']:,} dupes)")
        else:
            print(f"  {status} {name:<20} FAILED")
    print(f"\n  Total unique URLs : {stats.get('total_unique', 0):,}")
    if not ns.dry_run:
        print(f"  Filter size       : {stats.get('filter_mb', 0):.2f} MB")
        print(f"  Fill ratio        : {stats.get('fill_ratio', 0):.4%}")
        print(f"  Actual FPR        : {stats.get('actual_fpr', 0):.6%}")
        print(f"  Time              : {stats.get('elapsed_s', 0):.1f}s")
        print(f"  Saved to          : {stats.get('filter_path', '')}")
    print()


if __name__ == "__main__":
    main()