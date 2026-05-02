"""
dvara/app.py

FastAPI backend for dvara URL checking.

Endpoints:
    GET  /api/check?url=https://...   → check a URL against the bloom filter
    GET  /api/confirm?url=https://... → confirm if a bloom hit is truly malicious
    GET  /api/stats                   → filter stats + ingestion metadata
    POST /api/reload                  → reload filter from disk (called after ingestion)

Two-stage architecture:
    Stage 1 — Bloom filter (Redis bitstring): 0.3ms, handles 99%+ of checks
    Stage 2 — PostgreSQL confirmed_urls:      only hit on bloom filter positives

Environment variables (set in .env or Docker Compose):
    REDIS_URL       redis://localhost:6379
    DATABASE_URL    postgresql://user:pass@localhost:5432/dvara
    FILTER_PATH     ~/.dvara/filter.bin
    API_KEY         optional bearer token for /api/reload
"""

import hashlib
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dvara.bloom import BloomFilter

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Config from environment
# ------------------------------------------------------------------

REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dvara:dvara@localhost:5432/dvara")
FILTER_PATH  = os.getenv("FILTER_PATH", os.path.join(os.path.expanduser("~"), ".dvara", "filter.bin"))
API_KEY      = os.getenv("API_KEY", "")   # empty = no auth required

# ------------------------------------------------------------------
# App state — loaded once at startup
# ------------------------------------------------------------------

class AppState:
    bloom: Optional[BloomFilter] = None
    bloom_loaded_at: Optional[datetime] = None
    redis = None          # redis.asyncio client — injected at startup
    db_pool = None        # asyncpg pool — injected at startup


state = AppState()


# ------------------------------------------------------------------
# Lifespan — startup / shutdown
# ------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load bloom filter and open connections on startup."""
    # ---- Bloom filter ----
    await _load_bloom()

    # ---- Redis (optional — graceful degradation if unavailable) ----
    try:
        import redis.asyncio as aioredis
        state.redis = aioredis.from_url(REDIS_URL, decode_responses=False)
        await state.redis.ping()
        log.info("Redis connected: %s", REDIS_URL)
    except Exception as e:
        log.warning("Redis unavailable (%s) — running without Redis cache", e)
        state.redis = None

    # ---- PostgreSQL (optional — graceful degradation) ----
    try:
        import asyncpg
        state.db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
        log.info("PostgreSQL connected")
    except Exception as e:
        log.warning("PostgreSQL unavailable (%s) — confirm stage disabled", e)
        state.db_pool = None

    yield

    # ---- Shutdown ----
    if state.redis:
        await state.redis.aclose()
    if state.db_pool:
        await state.db_pool.close()


async def _load_bloom() -> None:
    """Load or reload the bloom filter from disk."""
    if not os.path.exists(FILTER_PATH):
        log.warning("Filter file not found at %s — run ingestion first", FILTER_PATH)
        state.bloom = None
        return
    state.bloom = BloomFilter.from_file(FILTER_PATH)
    state.bloom_loaded_at = datetime.now(timezone.utc)
    log.info("Bloom filter loaded: %s", state.bloom)


# ------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------

app = FastAPI(
    title="dvara API",
    description="High-speed malicious URL detection using a Bloom Filter",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Response models
# ------------------------------------------------------------------

class CheckResponse(BaseModel):
    url: str
    result: str          # "CLEAN" | "MALICIOUS" | "SUSPICIOUS" | "ERROR"
    reason: Optional[str] = None
    source: Optional[str] = None
    category: Optional[str] = None
    latency_ms: float
    stage: str           # "bloom" | "db" | "error"
    checked_at: str


class StatsResponse(BaseModel):
    filter_loaded: bool
    filter_path: str
    filter_size_mb: Optional[float]
    capacity: Optional[int]
    count: Optional[int]
    fill_ratio: Optional[float]
    target_fpr: Optional[float]
    actual_fpr: Optional[float]
    loaded_at: Optional[str]
    redis_connected: bool
    db_connected: bool


# ------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------

def require_bloom():
    if state.bloom is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bloom filter not loaded. Run ingestion first.",
        )
    return state.bloom


def require_api_key(request: Request):
    if not API_KEY:
        return   # auth disabled
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_KEY}":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@app.get("/api/check", response_model=CheckResponse)
async def check_url(
    url: str = Query(..., description="URL to check", min_length=1),
    bloom: BloomFilter = Depends(require_bloom),
):
    """
    Two-stage URL check:
      Stage 1 — Bloom filter (always): O(k) bit lookups, ~0.3ms
      Stage 2 — PostgreSQL (only on bloom hit): confirms true malicious vs false positive
    """
    t0 = time.perf_counter()
    checked_at = datetime.now(timezone.utc).isoformat()

    # ---- Stage 1: bloom filter ----
    in_bloom = bloom.contains(url)

    if not in_bloom:
        # Bloom says clean → definitely clean (zero false negatives)
        latency_ms = (time.perf_counter() - t0) * 1000
        return CheckResponse(
            url=url,
            result="CLEAN",
            latency_ms=round(latency_ms, 3),
            stage="bloom",
            checked_at=checked_at,
        )

    # ---- Stage 2: DB confirm ----
    if state.db_pool:
        try:
            async with state.db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT source, category FROM confirmed_urls WHERE url = $1 LIMIT 1",
                    url,
                )
            latency_ms = (time.perf_counter() - t0) * 1000
            if row:
                return CheckResponse(
                    url=url,
                    result="MALICIOUS",
                    source=row["source"],
                    category=row["category"],
                    latency_ms=round(latency_ms, 3),
                    stage="db",
                    checked_at=checked_at,
                )
            else:
                # Bloom hit but not in DB → false positive
                return CheckResponse(
                    url=url,
                    result="SUSPICIOUS",
                    reason="Bloom filter hit but not confirmed in database (possible false positive)",
                    latency_ms=round(latency_ms, 3),
                    stage="db",
                    checked_at=checked_at,
                )
        except Exception as e:
            log.error("DB confirm failed: %s", e)

    # DB unavailable — return bloom hit as suspicious
    latency_ms = (time.perf_counter() - t0) * 1000
    return CheckResponse(
        url=url,
        result="SUSPICIOUS",
        reason="Bloom filter hit — DB confirm unavailable",
        latency_ms=round(latency_ms, 3),
        stage="bloom",
        checked_at=checked_at,
    )


@app.get("/api/confirm")
async def confirm_url(
    url: str = Query(..., description="URL to look up in confirmed database"),
):
    """Direct DB lookup — bypasses bloom filter. Used for debugging."""
    if not state.db_pool:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT url, source, category, ingested_at FROM confirmed_urls WHERE url = $1",
            url,
        )
    if not row:
        return JSONResponse({"found": False, "url": url})
    return JSONResponse({
        "found": True,
        "url": row["url"],
        "source": row["source"],
        "category": row["category"],
        "ingested_at": row["ingested_at"].isoformat() if row["ingested_at"] else None,
    })


@app.get("/api/stats", response_model=StatsResponse)
async def stats():
    """Return filter metadata and connection status."""
    bf = state.bloom
    filter_size_mb = None
    if os.path.exists(FILTER_PATH):
        filter_size_mb = round(os.path.getsize(FILTER_PATH) / 1024 / 1024, 2)

    return StatsResponse(
        filter_loaded=bf is not None,
        filter_path=FILTER_PATH,
        filter_size_mb=filter_size_mb,
        capacity=bf.capacity if bf else None,
        count=bf._count if bf else None,
        fill_ratio=round(bf.fill_ratio, 6) if bf else None,
        target_fpr=bf.error_rate if bf else None,
        actual_fpr=round(bf.actual_fpr, 8) if bf else None,
        loaded_at=state.bloom_loaded_at.isoformat() if state.bloom_loaded_at else None,
        redis_connected=state.redis is not None,
        db_connected=state.db_pool is not None,
    )


@app.post("/api/reload")
async def reload_filter(_: None = Depends(require_api_key)):
    """
    Reload the bloom filter from disk.
    Called by the APScheduler ingestion job after a fresh filter is written.
    """
    await _load_bloom()
    if state.bloom is None:
        raise HTTPException(status_code=503, detail="Filter file not found after reload")
    return {"reloaded": True, "loaded_at": state.bloom_loaded_at.isoformat()}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "filter_loaded": state.bloom is not None,
        "redis": state.redis is not None,
        "db": state.db_pool is not None,
    }
