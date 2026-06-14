"""
dvara/app.py

FastAPI backend for dvara URL checking.
"""
import hashlib
import logging
import os
import shutil
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from dvara.bloom import BloomFilter

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://dvara:dvara@localhost:5432/dvara"
)

FILTER_PATH = os.getenv(
    "FILTER_PATH",
    os.path.join(os.path.expanduser("~"), ".dvara", "filter.bin")
)

API_KEY = os.getenv("API_KEY", "")

# ------------------------------------------------------------------
# App State
# ------------------------------------------------------------------

class AppState:
    bloom: Optional[BloomFilter] = None
    bloom_loaded_at: Optional[datetime] = None
    redis = None
    db_pool = None


state = AppState()

# ------------------------------------------------------------------
# Lifespan
# ------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):

    await _load_bloom()

    # Redis
    try:
        import redis.asyncio as aioredis

        state.redis = aioredis.from_url(
            REDIS_URL,
            decode_responses=False
        )

        await state.redis.ping()

        log.info("Redis connected")

    except Exception as e:
        log.warning("Redis unavailable: %s", e)
        state.redis = None

    # PostgreSQL
    try:
        import asyncpg

        state.db_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=2,
            max_size=10,
        )

        log.info("PostgreSQL connected")

    except Exception as e:
        log.warning("PostgreSQL unavailable: %s", e)
        state.db_pool = None

    yield

    # Shutdown
    if state.redis:
        await state.redis.aclose()

    if state.db_pool:
        await state.db_pool.close()


async def _load_bloom():

    if not os.path.exists(FILTER_PATH):
        log.warning(
            "Filter file not found at %s",
            FILTER_PATH
        )
        state.bloom = None
        return

    state.bloom = BloomFilter.from_file(FILTER_PATH)

    state.bloom_loaded_at = datetime.now(timezone.utc)

    log.info("Bloom filter loaded")

# ------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------

app = FastAPI(
    title="dvara API",
    description="Malicious URL detection",
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
# Response Models
# ------------------------------------------------------------------

class CheckResponse(BaseModel):
    url: str
    result: str
    reason: Optional[str] = None
    latency_ms: float
    stage: str
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
            detail="Bloom filter not loaded",
        )

    return state.bloom


def require_api_key(request: Request):

    if not API_KEY:
        return

    auth = request.headers.get("Authorization", "")

    if auth != f"Bearer {API_KEY}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------

@app.get("/api/check", response_model=CheckResponse)
async def check_url(
    url: str = Query(...),
    bloom: BloomFilter = Depends(require_bloom),
):

    t0 = time.perf_counter()

    checked_at = datetime.now(timezone.utc).isoformat()

    # Stage 1 — Bloom Filter
    in_bloom = bloom.contains(url)

    if not in_bloom:

        latency_ms = (time.perf_counter() - t0) * 1000

        return CheckResponse(
            url=url,
            result="CLEAN",
            latency_ms=round(latency_ms, 3),
            stage="bloom",
            checked_at=checked_at,
        )

    # Stage 2 — PostgreSQL Confirm
    if state.db_pool:

        try:
            url_hash = hashlib.sha256(
                url.encode()
            ).hexdigest()

            async with state.db_pool.acquire() as conn:

                row = await conn.fetchrow(
                    """
                    SELECT url
                    FROM confirmed_urls
                    WHERE url_hash = $1
                    LIMIT 1
                    """,
                    url_hash,
                )

            latency_ms = (time.perf_counter() - t0) * 1000

            if row:

                return CheckResponse(
                    url=url,
                    result="MALICIOUS",
                    latency_ms=round(latency_ms, 3),
                    stage="db",
                    checked_at=checked_at,
                )

            else:

                return CheckResponse(
                    url=url,
                    result="SUSPICIOUS",
                    reason="Bloom hit but not confirmed in DB",
                    latency_ms=round(latency_ms, 3),
                    stage="db",
                    checked_at=checked_at,
                )

        except Exception as e:
            log.error("DB confirm failed: %s", e)

    latency_ms = (time.perf_counter() - t0) * 1000

    return CheckResponse(
        url=url,
        result="SUSPICIOUS",
        reason="Bloom filter hit — DB unavailable",
        latency_ms=round(latency_ms, 3),
        stage="bloom",
        checked_at=checked_at,
    )


@app.get("/api/confirm")
async def confirm_url(
    url: str = Query(...),
):

    if not state.db_pool:
        raise HTTPException(
            status_code=503,
            detail="Database not connected"
        )

    url_hash = hashlib.sha256(
        url.encode()
    ).hexdigest()

    async with state.db_pool.acquire() as conn:

        row = await conn.fetchrow(
            """
            SELECT url
            FROM confirmed_urls
            WHERE url_hash = $1
            LIMIT 1
            """,
            url_hash,
        )

    if not row:

        return JSONResponse({
            "found": False,
            "url": url,
        })

    return JSONResponse({
        "found": True,
        "url": row["url"],
    })


@app.get("/api/stats", response_model=StatsResponse)
async def stats():

    bf = state.bloom

    filter_size_mb = None

    if os.path.exists(FILTER_PATH):
        filter_size_mb = round(
            os.path.getsize(FILTER_PATH) / 1024 / 1024,
            2
        )

    return StatsResponse(
        filter_loaded=bf is not None,
        filter_path=FILTER_PATH,
        filter_size_mb=filter_size_mb,
        capacity=bf.capacity if bf else None,
        count=bf._count if bf else None,
        fill_ratio=round(bf.fill_ratio, 6) if bf else None,
        target_fpr=bf.error_rate if bf else None,
        actual_fpr=round(bf.actual_fpr, 8) if bf else None,
        loaded_at=state.bloom_loaded_at.isoformat()
        if state.bloom_loaded_at else None,
        redis_connected=state.redis is not None,
        db_connected=state.db_pool is not None,
    )


@app.post("/api/reload")
async def reload_filter(
    _: None = Depends(require_api_key)
):

    await _load_bloom()

    if state.bloom is None:
        raise HTTPException(
            status_code=503,
            detail="Filter not loaded",
        )

    return {
        "reloaded": True,
        "loaded_at": state.bloom_loaded_at.isoformat(),
    }


@app.get("/health")
async def health():

    return {
        "status": "ok",
        "filter_loaded": state.bloom is not None,
        "redis": state.redis is not None,
        "db": state.db_pool is not None,
    }

# ------------------------------------------------------------------
# Static Frontend
# ------------------------------------------------------------------

import os
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
