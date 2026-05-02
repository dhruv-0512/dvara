-- docker/init.sql
-- Run automatically by PostgreSQL on first container start

-- ------------------------------------------------------------------
-- confirmed_urls — the source of truth for malicious URLs
-- Populated by ingestion.py, queried by Stage 2 of /api/check
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS confirmed_urls (
    id          BIGSERIAL PRIMARY KEY,
    url         TEXT        NOT NULL,
    source      TEXT        NOT NULL,   -- 'urlhaus' | 'phishtank' | 'openphish'
    category    TEXT,                   -- 'malware' | 'phishing' | 'botnet' etc.
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT confirmed_urls_url_unique UNIQUE (url)
);

-- Index for the Stage 2 lookup: WHERE url = $1
CREATE INDEX IF NOT EXISTS idx_confirmed_urls_url
    ON confirmed_urls (url);

-- ------------------------------------------------------------------
-- check_log — optional audit trail of every API check
-- Useful for stats, dashboards, and rate limiting later
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS check_log (
    id          BIGSERIAL PRIMARY KEY,
    url         TEXT        NOT NULL,
    result      TEXT        NOT NULL,   -- 'CLEAN' | 'MALICIOUS' | 'SUSPICIOUS'
    stage       TEXT        NOT NULL,   -- 'bloom' | 'db'
    latency_ms  NUMERIC(10, 3),
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for time-based queries (stats endpoint)
CREATE INDEX IF NOT EXISTS idx_check_log_checked_at
    ON check_log (checked_at DESC);

-- ------------------------------------------------------------------
-- ingestion_runs — metadata about each ingestion job
-- ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ingestion_runs (
    id           BIGSERIAL PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ,
    url_count    INTEGER,
    filter_size  BIGINT,     -- bytes
    status       TEXT        NOT NULL DEFAULT 'running',  -- 'running' | 'success' | 'failed'
    error        TEXT
);
