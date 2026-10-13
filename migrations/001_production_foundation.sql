-- ============================================================
-- NETWATCH PRODUCTION FOUNDATION
-- Migration 001
--
-- Establishes:
--   - Organizations
--   - Human authentication
--   - Organization memberships / RBAC
--   - Authentication sessions
--   - Collector/agent authentication
--   - Agent enrollment
--   - Heartbeat monitoring
--   - Current device state
--   - Device profiles
--   - Historical observations
--   - Idempotent collector uploads
--   - Security events
--   - Persistent alerts
--   - Production query indexes
-- ============================================================


-- ============================================================
-- ORGANIZATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    org_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- USERS
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,

    -- Legacy column retained temporarily for compatibility.
    -- New authentication code should use password_hash instead.
    password TEXT,

    role TEXT DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Secure password storage
ALTER TABLE users
ADD COLUMN IF NOT EXISTS password_hash TEXT;


-- Account activation/deactivation
ALTER TABLE users
ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;


-- Most recent successful login
ALTER TABLE users
ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;


-- Tracks account updates
ALTER TABLE users
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();


-- User lookup index
--
-- NOTE:
-- We intentionally do NOT create idx_users_org_id.
-- Users belong to organizations through org_memberships rather
-- than a direct users.org_id column.
CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);


-- ============================================================
-- ORGANIZATION MEMBERSHIPS / RBAC
-- ============================================================

CREATE TABLE IF NOT EXISTS org_memberships (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT NOT NULL
        REFERENCES organizations(org_id)
        ON DELETE CASCADE,

    user_id TEXT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    role TEXT NOT NULL
        CHECK (
            role IN (
                'OWNER',
                'ADMIN',
                'OPERATOR',
                'VIEWER'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (org_id, user_id)
);


CREATE INDEX IF NOT EXISTS idx_org_memberships_user
ON org_memberships(user_id);


CREATE INDEX IF NOT EXISTS idx_org_memberships_org
ON org_memberships(org_id);


-- ============================================================
-- AUTHENTICATION SESSIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,

    user_id TEXT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
ON auth_sessions(user_id);


CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires
ON auth_sessions(expires_at);


-- ============================================================
-- AGENTS / COLLECTORS
-- ============================================================

CREATE TABLE IF NOT EXISTS agents (
    id SERIAL PRIMARY KEY,

    agent_id TEXT UNIQUE NOT NULL,

    -- Legacy plaintext API-key column retained temporarily.
    -- New authentication code should use api_key_hash.
    api_key TEXT UNIQUE,

    org_id TEXT NOT NULL,

    network TEXT,

    last_seen TIMESTAMPTZ
);


-- Hashed collector credential
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS api_key_hash TEXT;


-- Subnet the collector is expected to monitor
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS network_cidr TEXT;


-- Collector lifecycle state
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';


ALTER TABLE agents
ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();


ALTER TABLE agents
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();


CREATE UNIQUE INDEX IF NOT EXISTS uq_agents_api_key_hash
ON agents(api_key_hash)
WHERE api_key_hash IS NOT NULL;


CREATE INDEX IF NOT EXISTS idx_agents_org
ON agents(org_id);


-- Retained for global stale-agent queries
CREATE INDEX IF NOT EXISTS idx_agents_last_seen
ON agents(last_seen);


-- Tenant-aware health lookup.
-- Preserved from the previous security baseline.
CREATE INDEX IF NOT EXISTS idx_agents_org_last_seen
ON agents(org_id, last_seen DESC);


-- ============================================================
-- AGENT ENROLLMENT TOKENS
-- ============================================================

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    token_hash TEXT PRIMARY KEY,

    org_id TEXT NOT NULL
        REFERENCES organizations(org_id)
        ON DELETE CASCADE,

    created_by TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    used_at TIMESTAMPTZ,

    used_by_agent_id TEXT
);


CREATE INDEX IF NOT EXISTS idx_agent_enrollment_org
ON agent_enrollment_tokens(org_id);


CREATE INDEX IF NOT EXISTS idx_agent_enrollment_expires
ON agent_enrollment_tokens(expires_at);


-- ============================================================
-- HEARTBEATS
-- ============================================================

CREATE TABLE IF NOT EXISTS heartbeats (
    id BIGSERIAL PRIMARY KEY,

    agent_id TEXT NOT NULL,

    org_id TEXT NOT NULL,

    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_heartbeats_agent_time
ON heartbeats(agent_id, timestamp DESC);


-- This already covers the old:
--
-- idx_heartbeats_org_timestamp
--
-- so a second equivalent index is intentionally not created.
CREATE INDEX IF NOT EXISTS idx_heartbeats_org_time
ON heartbeats(org_id, timestamp DESC);


-- ============================================================
-- DEVICES
--
-- This table represents CURRENT DEVICE STATE.
-- Historical observations belong in device_observations.
-- ============================================================

CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT,

    network TEXT,

    ip TEXT,

    mac TEXT,

    vendor TEXT,

    level TEXT,

    score INTEGER,

    timestamp TIMESTAMPTZ DEFAULT NOW()
);


ALTER TABLE devices
ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;


ALTER TABLE devices
ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;


ALTER TABLE devices
ADD COLUMN IF NOT EXISTS last_agent_id TEXT;


-- Populate lifecycle timestamps for existing rows.
UPDATE devices
SET
    first_seen = COALESCE(first_seen, timestamp, NOW()),
    last_seen = COALESCE(last_seen, timestamp, NOW())
WHERE
    first_seen IS NULL
    OR last_seen IS NULL;


-- Normalize MAC addresses before enforcing uniqueness.
UPDATE devices
SET mac = LOWER(mac)
WHERE mac IS NOT NULL;


-- Remove duplicate historical/current rows before creating the
-- current-state uniqueness guarantee.
--
-- For duplicate (org_id, mac) records, the row with the highest
-- ID is retained.
DELETE FROM devices older
USING devices newer
WHERE
    older.id < newer.id
    AND older.org_id = newer.org_id
    AND LOWER(COALESCE(older.mac, ''))
        = LOWER(COALESCE(newer.mac, ''))
    AND COALESCE(older.mac, '') <> '';


-- One current device record per organization + MAC.
--
-- This is the constraint required by:
--
-- ON CONFLICT (org_id, mac)
--
CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_org_mac
ON devices(org_id, mac);


CREATE INDEX IF NOT EXISTS idx_devices_org_score
ON devices(org_id, score DESC);


CREATE INDEX IF NOT EXISTS idx_devices_org_last_seen
ON devices(org_id, last_seen DESC);


-- Preserved from the previous security baseline.
-- Useful for queries involving the legacy/current observation
-- timestamp field while the application transitions to last_seen.
CREATE INDEX IF NOT EXISTS idx_devices_org_timestamp
ON devices(org_id, timestamp DESC);


-- ============================================================
-- DEVICE PROFILES
-- ============================================================

CREATE TABLE IF NOT EXISTS device_profiles (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT,

    mac TEXT,

    vendor TEXT,

    trust_score INTEGER DEFAULT 50,

    threat_count INTEGER DEFAULT 0,

    times_seen INTEGER DEFAULT 1,

    reputation TEXT DEFAULT 'UNKNOWN',

    first_seen TIMESTAMPTZ DEFAULT NOW(),

    last_seen TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, mac)
);


ALTER TABLE device_profiles
ADD COLUMN IF NOT EXISTS trusted BOOLEAN NOT NULL DEFAULT FALSE;


ALTER TABLE device_profiles
ADD COLUMN IF NOT EXISTS last_risk_score INTEGER NOT NULL DEFAULT 0;


ALTER TABLE device_profiles
ADD COLUMN IF NOT EXISTS last_risk_level TEXT NOT NULL DEFAULT 'LOW';


-- Normalize MAC addresses.
UPDATE device_profiles
SET mac = LOWER(mac)
WHERE mac IS NOT NULL;


-- Remove duplicate profiles where older databases may not have
-- correctly enforced the intended device identity.
DELETE FROM device_profiles older
USING device_profiles newer
WHERE
    older.id < newer.id
    AND older.org_id = newer.org_id
    AND LOWER(COALESCE(older.mac, ''))
        = LOWER(COALESCE(newer.mac, ''))
    AND COALESCE(older.mac, '') <> '';


CREATE INDEX IF NOT EXISTS idx_device_profiles_org
ON device_profiles(org_id);


CREATE INDEX IF NOT EXISTS idx_device_profiles_trusted
ON device_profiles(org_id, trusted);


-- Preserved from the previous security baseline.
-- Supports tenant-scoped trust/risk ordering.
CREATE INDEX IF NOT EXISTS idx_device_profiles_org_trust
ON device_profiles(org_id, trust_score);


-- ============================================================
-- DEVICE OBSERVATIONS
--
-- Append-only historical device telemetry.
-- ============================================================

CREATE TABLE IF NOT EXISTS device_observations (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT NOT NULL,

    agent_id TEXT NOT NULL,

    network TEXT,

    network_cidr TEXT,

    ip TEXT NOT NULL,

    mac TEXT NOT NULL,

    vendor TEXT,

    risk_level TEXT NOT NULL,

    risk_score INTEGER NOT NULL,

    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,

    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_observations_org_time
ON device_observations(org_id, observed_at DESC);


CREATE INDEX IF NOT EXISTS idx_observations_org_mac_time
ON device_observations(org_id, mac, observed_at DESC);


CREATE INDEX IF NOT EXISTS idx_observations_agent_time
ON device_observations(agent_id, observed_at DESC);


-- ============================================================
-- AGENT UPLOAD BATCHES
--
-- Used for upload idempotency.
-- Prevents duplicate processing if a collector retries a batch.
-- ============================================================

CREATE TABLE IF NOT EXISTS agent_upload_batches (
    org_id TEXT NOT NULL,

    agent_id TEXT NOT NULL,

    batch_id TEXT NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (
        org_id,
        agent_id,
        batch_id
    )
);


CREATE INDEX IF NOT EXISTS idx_upload_batches_received
ON agent_upload_batches(received_at DESC);


-- ============================================================
-- SECURITY EVENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT NOT NULL,

    event_type TEXT NOT NULL,

    device_mac TEXT,

    device_ip TEXT,

    severity TEXT NOT NULL,

    score INTEGER NOT NULL DEFAULT 0,

    title TEXT NOT NULL,

    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,

    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_security_events_org_time
ON security_events(org_id, observed_at DESC);


CREATE INDEX IF NOT EXISTS idx_security_events_device
ON security_events(
    org_id,
    device_mac,
    observed_at DESC
);


-- ============================================================
-- ALERTS
-- ============================================================

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,

    org_id TEXT NOT NULL,

    rule_key TEXT NOT NULL,

    device_mac TEXT,

    severity TEXT NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'OPEN'
        CHECK (
            status IN (
                'OPEN',
                'ACKNOWLEDGED',
                'RESOLVED'
            )
        ),

    title TEXT NOT NULL,

    description TEXT,

    score INTEGER NOT NULL DEFAULT 0,

    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    occurrences INTEGER NOT NULL DEFAULT 1,

    acknowledged_at TIMESTAMPTZ,

    acknowledged_by TEXT,

    resolved_at TIMESTAMPTZ,

    resolved_by TEXT
);


CREATE INDEX IF NOT EXISTS idx_alerts_org_status
ON alerts(
    org_id,
    status,
    last_seen DESC
);


CREATE INDEX IF NOT EXISTS idx_alerts_device
ON alerts(
    org_id,
    device_mac,
    last_seen DESC
);
