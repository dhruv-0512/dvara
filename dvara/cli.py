"""
dvara/cli.py

Click-based CLI for dvara.

Commands:
    dvara check <url>        — check a URL (online mode, hits API)
    dvara check <url> --offline — check locally against cached filter
    dvara update             — download latest filter from API
    dvara stats              — show filter + API stats
    dvara ingest             — run ingestion pipeline manually

Usage examples:
    dvara check https://suspicious-site.com
    dvara check https://suspicious-site.com --offline
    dvara update
    dvara stats
"""

import os
import sys
import time
from datetime import datetime, timezone

import click
import requests

from dvara.bloom import BloomFilter
from dvara.config import API_BASE_URL, DEFAULT_FILTER_PATH, VERSION

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

# ANSI colours (disabled on Windows if no ANSI support)
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def _color(text: str, code: str) -> str:
    """Wrap text in ANSI colour code if stdout is a terminal."""
    if sys.stdout.isatty():
        return f"{code}{text}{RESET}"
    return text

def _load_local_filter() -> BloomFilter | None:
    """Load filter — local cache first, fall back to bundled."""
    if os.path.exists(DEFAULT_FILTER_PATH):
        return BloomFilter.from_file(DEFAULT_FILTER_PATH)
    from dvara.config import BUNDLED_FILTER_PATH
    if os.path.exists(BUNDLED_FILTER_PATH):
        return BloomFilter.from_file(BUNDLED_FILTER_PATH)
    return None

def _format_latency(ms: float) -> str:
    return f"{ms:.1f}ms"


# ------------------------------------------------------------------
# CLI group
# ------------------------------------------------------------------

@click.group()
@click.version_option(version=VERSION, prog_name="dvara")
def cli():
    """dvara — malicious URL detection using a Bloom Filter."""
    pass


# ------------------------------------------------------------------
# check
# ------------------------------------------------------------------

@cli.command()
@click.argument("url")
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Check locally using cached filter (no network call to API).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output result as JSON.",
)
def check(url: str, offline: bool, output_json: bool):
    """Check a URL against the malicious URL database.

    \b
    Examples:
        dvara check https://suspicious-site.com
        dvara check https://suspicious-site.com --offline
    """
    if offline:
        _check_offline(url, output_json)
    else:
        _check_online(url, output_json)


def _check_online(url: str, output_json: bool):
    """Hit the API for a two-stage bloom + DB check."""
    t0 = time.perf_counter()
    try:
        resp = requests.get(
            f"{API_BASE_URL}/api/check",
            params={"url": url},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.ConnectionError:
        click.echo(_color("✗ Cannot reach dvara API. Try --offline mode.", RED))
        sys.exit(1)
    except requests.Timeout:
        click.echo(_color("✗ API request timed out. Try --offline mode.", RED))
        sys.exit(1)
    except Exception as e:
        click.echo(_color(f"✗ Error: {e}", RED))
        sys.exit(1)

    if output_json:
        import json
        click.echo(json.dumps(data, indent=2))
        return

    result   = data.get("result", "ERROR")
    latency  = data.get("latency_ms", 0)
    source   = data.get("source")
    category = data.get("category")
    reason   = data.get("reason")

    _print_result(url, result, latency, source, category, reason, mode="online")


def _check_offline(url: str, output_json: bool):
    """Check locally using the cached bloom filter."""
    bf = _load_local_filter()
    if bf is None:
        click.echo(_color(
            f"✗ No local filter found at {DEFAULT_FILTER_PATH}.\n"
            "  Run: dvara update",
            RED,
        ))
        sys.exit(1)

    t0 = time.perf_counter()
    hit = bf.contains(url)
    latency_ms = (time.perf_counter() - t0) * 1000

    result = "SUSPICIOUS" if hit else "CLEAN"

    if output_json:
        import json
        click.echo(json.dumps({
            "url": url,
            "result": result,
            "latency_ms": round(latency_ms, 3),
            "mode": "offline",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))
        return

    reason = "Bloom filter hit — run online check to confirm" if hit else None
    _print_result(url, result, latency_ms, None, None, reason, mode="offline")


def _print_result(
    url: str,
    result: str,
    latency_ms: float,
    source: str | None,
    category: str | None,
    reason: str | None,
    mode: str,
):
    latency_str = _format_latency(latency_ms)

    if result == "CLEAN":
        icon  = "✅"
        label = _color("CLEAN", GREEN)
    elif result == "MALICIOUS":
        icon  = "🚨"
        label = _color("MALICIOUS", RED)
    elif result == "SUSPICIOUS":
        icon  = "⚠️ "
        label = _color("SUSPICIOUS", YELLOW)
    else:
        icon  = "✗"
        label = _color("ERROR", RED)

    # Main result line
    parts = [icon, label]
    if source:
        parts.append(_color(f"| {source}", CYAN))
    if category:
        parts.append(_color(f"| {category}", CYAN))
    parts.append(_color(f"| {latency_str}", RESET))
    parts.append(_color(f"| {mode}", RESET))

    click.echo(" ".join(parts))

    # URL (truncated if long)
    display_url = url if len(url) <= 80 else url[:77] + "..."
    click.echo(f"  {_color(display_url, BOLD)}")

    # Extra info
    if reason:
        click.echo(f"  {_color(reason, YELLOW)}")


# ------------------------------------------------------------------
# update
# ------------------------------------------------------------------

@cli.command()
@click.option(
    "--output",
    default=DEFAULT_FILTER_PATH,
    show_default=True,
    help="Path to save the downloaded filter.",
)
def update(output: str):
    """Download the latest filter binary from the API.

    \b
    Example:
        dvara update
    """
    click.echo(f"Downloading latest filter from {API_BASE_URL} …")

    try:
        resp = requests.get(f"{API_BASE_URL}/filter/download", timeout=60, stream=True)
        resp.raise_for_status()
    except requests.ConnectionError:
        click.echo(_color("✗ Cannot reach dvara API.", RED))
        sys.exit(1)
    except requests.HTTPError as e:
        # Filter download endpoint not implemented yet — fall back to local ingestion
        click.echo(_color(
            f"⚠  Filter download endpoint not available ({e}).\n"
            "   Run ingestion locally instead:\n"
            "   python -m dvara.ingestion",
            YELLOW,
        ))
        sys.exit(1)

    os.makedirs(os.path.dirname(output), exist_ok=True) if os.path.dirname(output) else None
    total = 0
    with open(output, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            total += len(chunk)

    size_kb = total / 1024
    click.echo(_color(f"✅ Filter saved to {output} ({size_kb:.0f} KB)", GREEN))


# ------------------------------------------------------------------
# stats
# ------------------------------------------------------------------

@cli.command()
def stats():
    """Show filter and API statistics.

    \b
    Example:
        dvara stats
    """
    # ---- Local filter info ----
    click.echo(_color("── Local Filter ──", BOLD))
    bf = _load_local_filter()
    if bf:
        size_mb = os.path.getsize(DEFAULT_FILTER_PATH) / 1024 / 1024
        click.echo(f"  Path:       {DEFAULT_FILTER_PATH}")
        click.echo(f"  Size:       {size_mb:.2f} MB")
        click.echo(f"  URLs:       {bf._count:,}")
        click.echo(f"  Capacity:   {bf.capacity:,}")
        click.echo(f"  Fill ratio: {bf.fill_ratio:.4%}")
        click.echo(f"  Target FPR: {bf.error_rate:.4%}")
        click.echo(f"  Actual FPR: {bf.actual_fpr:.6%}")
        click.echo(f"  k (hashes): {bf.k}")
    else:
        click.echo(_color(f"  No local filter at {DEFAULT_FILTER_PATH}", YELLOW))
        click.echo("  Run: dvara update")

    # ---- API stats ----
    click.echo("")
    click.echo(_color("── API ──", BOLD))
    try:
        resp = requests.get(f"{API_BASE_URL}/api/stats", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        click.echo(f"  Endpoint:   {API_BASE_URL}")
        click.echo(f"  Filter:     {'loaded' if data.get('filter_loaded') else 'not loaded'}")
        click.echo(f"  Redis:      {'connected' if data.get('redis_connected') else 'disconnected'}")
        click.echo(f"  Database:   {'connected' if data.get('db_connected') else 'disconnected'}")
        click.echo(f"  URLs:       {data.get('count', 'n/a'):,}" if data.get('count') else "  URLs:       n/a")
        click.echo(f"  Loaded at:  {data.get('loaded_at', 'n/a')}")
    except requests.ConnectionError:
        click.echo(_color(f"  API unreachable at {API_BASE_URL}", YELLOW))
    except Exception as e:
        click.echo(_color(f"  API error: {e}", YELLOW))


# ------------------------------------------------------------------
# ingest
# ------------------------------------------------------------------

@cli.command()
@click.option(
    "--output",
    default=DEFAULT_FILTER_PATH,
    show_default=True,
    help="Path to save the built filter.",
)
@click.option("--dry-run", is_flag=True, help="Fetch feeds but do not write files.")
def ingest(output: str, dry_run: bool):
    """Fetch threat feeds and rebuild the local filter.

    \b
    Example:
        dvara ingest
        dvara ingest --dry-run
    """
    from dvara.ingestion import main as ingestion_main
    args = ["--output", output]
    if dry_run:
        args.append("--dry-run")
    ingestion_main(args)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    cli()
