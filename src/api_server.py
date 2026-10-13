from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import ipaddress

import psycopg2
from psycopg2.extras import Json, RealDictCursor
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, join_room
from werkzeug.security import check_password_hash, generate_password_hash

from threat_engine import analyze_device, normalize_mac

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


# -----------------------------------------------------------------------------
# Logging / observability
# -----------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "fields") and isinstance(record.fields, dict):
            payload.update(record.fields)
        return json.dumps(payload, default=str)


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("netwatch")
logger.handlers.clear()
logger.addHandler(handler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
logger.propagate = False

STARTED_AT = time.time()
METRICS_LOCK = threading.Lock()
METRICS = {
    "requests_total": 0,
    "request_errors_total": 0,
    "uploads_total": 0,
    "uploaded_devices_total": 0,
    "heartbeats_total": 0,
}


def metric_inc(name: str, amount: int = 1) -> None:
    with METRICS_LOCK:
        METRICS[name] = METRICS.get(name, 0) + amount


# -----------------------------------------------------------------------------
# Flask / Socket.IO configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")

allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]

CORS(app, origins=allowed_origins, allow_headers=["Authorization", "Content-Type", "X-ORG-ID", "X-API-Key"])

socketio = SocketIO(
    app,
    cors_allowed_origins=allowed_origins,
    async_mode=os.getenv("SOCKETIO_ASYNC_MODE") or None,
)


# -----------------------------------------------------------------------------
# Database helpers
# -----------------------------------------------------------------------------


def get_db():
    url = os.getenv("DATABASE_URL")

    if url:
        return psycopg2.connect(url)

    password = os.getenv("DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "DATABASE_URL or DB_PASSWORD must be configured"
        )

    return psycopg2.connect(
        dbname=os.getenv("DB_NAME", "netwatch"),
        user=os.getenv("DB_USER", "postgres"),
        password=password,
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
    )


def dict_cursor(conn):
    return conn.cursor(cursor_factory=RealDictCursor)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return None


def normalize_org_id(value: str | None) -> str:
    value = (value or "").strip().upper()
    value = re.sub(r"[^A-Z0-9_-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:64]


def serialize_dt(value: Any) -> str | None:
    return value.isoformat() if value else None


# -----------------------------------------------------------------------------
# Request logging / generic error handling
# -----------------------------------------------------------------------------

@app.before_request
def before_request() -> None:
    g.request_started_at = time.perf_counter()
    metric_inc("requests_total")


@app.after_request
def after_request(response):
    duration_ms = round((time.perf_counter() - getattr(g, "request_started_at", time.perf_counter())) * 1000, 2)
    logger.info(
        "request_completed",
        extra={
            "fields": {
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            }
        },
    )
    if response.status_code >= 500:
        metric_inc("request_errors_total")
    return response


@app.errorhandler(Exception)
def handle_unexpected_error(exc: Exception):
    logger.exception(
        "unhandled_exception",
        extra={
            "fields": {
                "path": request.path,
                "method": request.method,
                "exception_type": type(exc).__name__,
                "exception": str(exc),
            }
        },
    )
    metric_inc("request_errors_total")
    return jsonify({"error": "Internal server error"}), 500


# -----------------------------------------------------------------------------
# Human authentication / tenant authorization
# -----------------------------------------------------------------------------


def bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header.split(" ", 1)[1].strip()
    return token or None


def load_human_session(require_org: bool = True) -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    token = bearer_token()
    if not token:
        return None, (jsonify({"error": "Missing bearer token"}), 401)

    token_hash = hash_token(token)
    org_id = normalize_org_id(request.headers.get("X-ORG-ID")) if require_org else None

    if require_org and not org_id:
        return None, (jsonify({"error": "Missing X-ORG-ID"}), 400)

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT s.user_id, u.email, s.expires_at
                FROM auth_sessions s
                JOIN users u ON u.user_id = s.user_id
                WHERE s.token_hash = %s
                  AND s.expires_at > NOW()
                """,
                (token_hash,),
            )
            session_row = cur.fetchone()

            if not session_row:
                return None, (jsonify({"error": "Invalid or expired session"}), 401)

            role = None
            if require_org:
                cur.execute(
                    """
                    SELECT role
                    FROM org_memberships
                    WHERE user_id = %s AND org_id = %s
                    """,
                    (session_row["user_id"], org_id),
                )
                membership = cur.fetchone()
                if not membership:
                    return None, (jsonify({"error": "Access denied for this organization"}), 403)
                role = membership["role"]

            cur.execute(
                "UPDATE auth_sessions SET last_used_at = NOW() WHERE token_hash = %s",
                (token_hash,),
            )
            conn.commit()

            return {
                "user_id": session_row["user_id"],
                "email": session_row["email"],
                "org_id": org_id,
                "role": role,
                "token_hash": token_hash,
            }, None
    finally:
        conn.close()


def require_user(*, roles: set[str] | None = None, require_org: bool = True):
    def decorator(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            auth, error = load_human_session(require_org=require_org)
            if error:
                return error

            if roles and auth["role"] not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            g.auth = auth
            return function(*args, **kwargs)

        return wrapper

    return decorator


def create_session(cur, user_id: str) -> tuple[str, datetime]:
    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)
    ttl_hours = int(os.getenv("SESSION_TTL_HOURS", "12"))
    expires_at = utcnow() + timedelta(hours=ttl_hours)

    cur.execute(
        """
        INSERT INTO auth_sessions(token_hash, user_id, expires_at)
        VALUES (%s, %s, %s)
        """,
        (token_hash, user_id, expires_at),
    )
    return raw_token, expires_at


@app.post("/auth/register")
def register_user():
    if os.getenv("ALLOW_PUBLIC_SIGNUP", "true").lower() not in {"1", "true", "yes", "on"}:
        return jsonify({"error": "Public signup is disabled"}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    org_name = str(data.get("org_name") or "").strip()
    org_id = normalize_org_id(data.get("org_id") or org_name)

    if not email or "@" not in email:
        return jsonify({"error": "A valid email address is required"}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must contain at least 12 characters"}), 400
    if not org_name or not org_id:
        return jsonify({"error": "Organization name is required"}), 400

    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(password)

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({"error": "Email is already registered"}), 409

            cur.execute("SELECT 1 FROM organizations WHERE org_id = %s", (org_id,))
            if cur.fetchone():
                return jsonify({"error": "Organization ID is already in use"}), 409

            cur.execute(
                "INSERT INTO organizations(org_id, name) VALUES (%s, %s)",
                (org_id, org_name),
            )
            cur.execute(
                """
                INSERT INTO users(user_id, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (user_id, email, password_hash),
            )
            cur.execute(
                """
                INSERT INTO org_memberships(org_id, user_id, role)
                VALUES (%s, %s, 'OWNER')
                """,
                (org_id, user_id),
            )
            raw_token, expires_at = create_session(cur, user_id)
            conn.commit()

        return jsonify(
            {
                "token": raw_token,
                "expires_at": expires_at.isoformat(),
                "user": {"user_id": user_id, "email": email},
                "organization": {"org_id": org_id, "name": org_name, "role": "OWNER"},
            }
        ), 201
    except psycopg2.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/auth/login")
def login_user():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                "SELECT user_id, email, password_hash FROM users WHERE email = %s",
                (email,),
            )
            user = cur.fetchone()

            if not user or not user["password_hash"]:
                return jsonify({"error": "Invalid email or password"}), 401

            try:
                password_valid = check_password_hash(
                    user["password_hash"],
                    password,
                )
            except (ValueError, TypeError) as exc:
                logger.error(
                    "invalid_password_hash",
                    extra={
                        "fields": {
                            "user_id": user["user_id"],
                            "exception_type": type(exc).__name__,
                        }
                    },
                )
                return jsonify({"error": "Invalid email or password"}), 401

            if not password_valid:
                return jsonify({"error": "Invalid email or password"}), 401

            cur.execute(
                """
                SELECT m.org_id, o.name, m.role
                FROM org_memberships m
                JOIN organizations o ON o.org_id = m.org_id
                WHERE m.user_id = %s
                ORDER BY m.created_at ASC
                """,
                (user["user_id"],),
            )
            organizations = cur.fetchall()
            if not organizations:
                return jsonify({"error": "User is not assigned to an organization"}), 403

            raw_token, expires_at = create_session(cur, user["user_id"])
            conn.commit()

        return jsonify(
            {
                "token": raw_token,
                "expires_at": expires_at.isoformat(),
                "user": {"user_id": user["user_id"], "email": user["email"]},
                "organizations": organizations,
                "default_org_id": organizations[0]["org_id"],
            }
        )
    finally:
        conn.close()


@app.get("/auth/me")
@require_user(require_org=False)
def auth_me():
    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT m.org_id, o.name, m.role
                FROM org_memberships m
                JOIN organizations o ON o.org_id = m.org_id
                WHERE m.user_id = %s
                ORDER BY o.name
                """,
                (g.auth["user_id"],),
            )
            organizations = cur.fetchall()
        return jsonify(
            {
                "user": {"user_id": g.auth["user_id"], "email": g.auth["email"]},
                "organizations": organizations,
            }
        )
    finally:
        conn.close()


@app.post("/auth/logout")
@require_user(require_org=False)
def logout_user():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM auth_sessions WHERE token_hash = %s", (g.auth["token_hash"],))
        conn.commit()
        return jsonify({"status": "logged_out"})
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Collector enrollment and authentication
# -----------------------------------------------------------------------------

@app.post("/agent-enrollment-tokens")
@require_user(roles={"OWNER", "ADMIN"})
def create_agent_enrollment_token():
    data = request.get_json(silent=True) or {}
    ttl_minutes = int(data.get("ttl_minutes") or 15)
    ttl_minutes = max(1, min(ttl_minutes, 60))

    raw_token = secrets.token_urlsafe(40)
    token_hash = hash_token(raw_token)
    expires_at = utcnow() + timedelta(minutes=ttl_minutes)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_enrollment_tokens(
                    token_hash, org_id, created_by, expires_at
                ) VALUES (%s, %s, %s, %s)
                """,
                (token_hash, g.auth["org_id"], g.auth["user_id"], expires_at),
            )
        conn.commit()
        return jsonify({"enrollment_token": raw_token, "expires_at": expires_at.isoformat()}), 201
    finally:
        conn.close()


@app.post("/agent/enroll")
def enroll_agent():
    data = request.get_json(silent=True) or {}
    enrollment_token = str(data.get("enrollment_token") or "")
    network = str(data.get("network") or "Unnamed Network").strip()[:128]
    network_cidr = str(data.get("network_cidr") or "").strip()[:128]

    if not enrollment_token:
        return jsonify({"error": "enrollment_token is required"}), 400
    if not network_cidr:
        return jsonify({"error": "network_cidr is required"}), 400

    token_hash = hash_token(enrollment_token)
    agent_id = str(uuid.uuid4())
    raw_api_key = secrets.token_urlsafe(48)
    api_key_hash = hash_token(raw_api_key)

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT org_id
                FROM agent_enrollment_tokens
                WHERE token_hash = %s
                  AND used_at IS NULL
                  AND expires_at > NOW()
                FOR UPDATE
                """,
                (token_hash,),
            )
            enrollment = cur.fetchone()
            if not enrollment:
                return jsonify({"error": "Invalid, expired, or already-used enrollment token"}), 401

            org_id = enrollment["org_id"]
            cur.execute(
                """
                INSERT INTO agents(
                    agent_id, api_key_hash, org_id, network, network_cidr, status
                ) VALUES (%s, %s, %s, %s, %s, 'ACTIVE')
                """,
                (agent_id, api_key_hash, org_id, network, network_cidr),
            )
            cur.execute(
                """
                UPDATE agent_enrollment_tokens
                SET used_at = NOW(), used_by_agent_id = %s
                WHERE token_hash = %s
                """,
                (agent_id, token_hash),
            )
            conn.commit()

        logger.info("agent_enrolled", extra={"fields": {"org_id": org_id, "agent_id": agent_id}})
        return jsonify({"agent_id": agent_id, "api_key": raw_api_key, "org_id": org_id}), 201
    except psycopg2.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/register")
def legacy_register_disabled():
    return jsonify(
        {
            "error": "Legacy unauthenticated registration is disabled",
            "human_signup": "/auth/register",
            "collector_enrollment": "/agent/enroll",
        }
    ), 410


def require_agent(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        raw_api_key = request.headers.get("X-API-Key", "").strip()
        org_id = normalize_org_id(request.headers.get("X-ORG-ID"))
        if not raw_api_key or not org_id:
            return jsonify({"error": "X-API-Key and X-ORG-ID are required"}), 401

        conn = get_db()
        try:
            with dict_cursor(conn) as cur:
                cur.execute(
                    """
                    SELECT agent_id, org_id, network, network_cidr, status
                    FROM agents
                    WHERE api_key_hash = %s
                      AND org_id = %s
                      AND status = 'ACTIVE'
                    """,
                    (hash_token(raw_api_key), org_id),
                )
                agent = cur.fetchone()
                if not agent:
                    return jsonify({"error": "Unauthorized collector"}), 401
                g.agent = agent
        finally:
            conn.close()

        return function(*args, **kwargs)

    return wrapper


# -----------------------------------------------------------------------------
# Health / metrics
# -----------------------------------------------------------------------------

@app.get("/")
def home():
    return jsonify({"name": "NetWatch API", "status": "online", "version": "2.0"})


@app.get("/health/live")
def health_live():
    return jsonify({"status": "alive", "uptime_seconds": int(time.time() - STARTED_AT)})


@app.get("/health/ready")
def health_ready():
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
                cur.execute("SELECT COUNT(*) FROM schema_migrations")
                migration_count = cur.fetchone()[0]
        finally:
            conn.close()

        return jsonify({"status": "ready", "database": "connected", "migrations": migration_count})
    except Exception:
        logger.exception("readiness_check_failed")
        return jsonify({"status": "not_ready", "database": "unavailable"}), 503


@app.get("/health")
def legacy_health():
    return health_ready()


@app.get("/metrics")
def metrics():
    configured_token = os.getenv("METRICS_TOKEN", "")
    if configured_token and not secrets.compare_digest(request.headers.get("X-Metrics-Token", ""), configured_token):
        return jsonify({"error": "Unauthorized"}), 401

    with METRICS_LOCK:
        snapshot = dict(METRICS)
    snapshot["uptime_seconds"] = int(time.time() - STARTED_AT)
    return jsonify(snapshot)


# -----------------------------------------------------------------------------
# Collector heartbeat / upload
# -----------------------------------------------------------------------------

@app.post("/heartbeat")
@require_agent
def heartbeat():
    data = request.get_json(silent=True) or {}

    network_metadata, network_error = validate_agent_network_metadata(data)

    if network_error:
        return jsonify({"error": network_error}), 400

    agent_id = g.agent["agent_id"]
    org_id = g.agent["org_id"]

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO heartbeats(agent_id, org_id) VALUES (%s, %s)",
                (agent_id, org_id),
            )

            cur.execute(
                """
                UPDATE agents
                SET network = COALESCE(%s, network),
                    network_cidr = COALESCE(%s, network_cidr),
                    last_seen = NOW(),
                    updated_at = NOW()
                WHERE agent_id = %s
                  AND org_id = %s
                """,
                (
                    network_metadata["network"],
                    network_metadata["network_cidr"],
                    agent_id,
                    org_id,
                ),
            )

        conn.commit()

    finally:
        conn.close()

    metric_inc("heartbeats_total")

    socketio.emit(
        "agent_update",
        {"agent_id": agent_id},
        to=f"org:{org_id}",
    )

    return jsonify({"status": "alive"})

    metric_inc("heartbeats_total")
    socketio.emit(
        "agent_update",
        {"agent_id": g.agent["agent_id"]},
        to=f"org:{g.agent['org_id']}",
    )
    return jsonify({"status": "alive"})


def validate_device_payload(device: Any) -> tuple[dict[str, str] | None, str | None]:
    if not isinstance(device, dict):
        return None, "Each device must be an object"

    ip = str(device.get("ip") or "").strip()
    mac = normalize_mac(device.get("mac"))
    vendor = str(device.get("vendor") or "Unknown").strip()[:128]

    if not ip:
        return None, "Device IP is required"
    if mac == "unknown":
        return None, "Device MAC is required"

    return {"ip": ip[:128], "mac": mac[:64], "vendor": vendor}, None

def validate_agent_network_metadata(data):
    network = str(data.get("network") or "").strip() or None
    network_cidr = str(data.get("network_cidr") or "").strip() or None
    agent_ip = str(data.get("agent_ip") or "").strip() or None

    if network and len(network) > 128:
        return None, "network name is too long"

    # Backward compatibility with older collectors.
    if network_cidr is None and agent_ip is None:
        return {
            "network": network,
            "network_cidr": None,
            "agent_ip": None,
        }, None

    if not network_cidr or not agent_ip:
        return None, "network_cidr and agent_ip must be supplied together"

    try:
        parsed_network = ipaddress.ip_network(
            network_cidr,
            strict=False,
        )
        parsed_ip = ipaddress.ip_address(agent_ip)

    except ValueError:
        return None, "invalid agent_ip or network_cidr"

    if parsed_network.version != 4 or parsed_ip.version != 4:
        return None, "only IPv4 collector networks are currently supported"

    if parsed_ip not in parsed_network:
        return None, (
            f"agent_ip {parsed_ip} does not belong to "
            f"network_cidr {parsed_network}"
        )

    if parsed_network.prefixlen < 8 or parsed_network.prefixlen > 30:
        return None, "collector network prefix must be between /8 and /30"

    return {
        "network": network,
        "network_cidr": str(parsed_network),
        "agent_ip": str(parsed_ip),
    }, None


def create_event(cur, *, org_id: str, event_type: str, device: dict[str, Any], risk: dict[str, Any], title: str) -> int:
    cur.execute(
        """
        INSERT INTO security_events(
            org_id, event_type, device_mac, device_ip, severity,
            score, title, evidence
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            org_id,
            event_type,
            device.get("mac"),
            device.get("ip"),
            risk["level"],
            risk["score"],
            title,
            Json({"reasons": risk.get("reasons", []), "confidence": risk.get("confidence")}),
        ),
    )
    return cur.fetchone()["id"]


def upsert_alert(
    cur,
    *,
    org_id: str,
    rule_key: str,
    device_mac: str,
    severity: str,
    title: str,
    description: str,
    score: int,
) -> int:
    cur.execute(
        """
        SELECT id
        FROM alerts
        WHERE org_id = %s
          AND rule_key = %s
          AND device_mac = %s
          AND status IN ('OPEN', 'ACKNOWLEDGED')
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE
        """,
        (org_id, rule_key, device_mac),
    )
    existing = cur.fetchone()

    if existing:
        alert_id = existing["id"]
        cur.execute(
            """
            UPDATE alerts
            SET severity = %s,
                title = %s,
                description = %s,
                score = %s,
                last_seen = NOW(),
                occurrences = occurrences + 1
            WHERE id = %s
            """,
            (severity, title, description, score, alert_id),
        )
        return alert_id

    cur.execute(
        """
        INSERT INTO alerts(
            org_id, rule_key, device_mac, severity, title, description, score
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (org_id, rule_key, device_mac, severity, title, description, score),
    )
    return cur.fetchone()["id"]


@app.post("/upload")
@require_agent
def upload_data():
    data = request.get_json(silent=True) or {}
    devices = data.get("devices", [])
    batch_id = str(data.get("batch_id") or "").strip()

    if not batch_id:
        return jsonify({"error": "batch_id is required"}), 400
    if not isinstance(devices, list):
        return jsonify({"error": "devices must be a list"}), 400
    if len(devices) > 4096:
        return jsonify({"error": "devices list exceeds the 4096-device limit"}), 413

    validated_devices: list[dict[str, str]] = []
    for index, device in enumerate(devices):
        validated, error = validate_device_payload(device)
        if error:
            return jsonify({"error": f"devices[{index}]: {error}"}), 400
        validated_devices.append(validated)

    org_id = g.agent["org_id"]
    agent_id = g.agent["agent_id"]
    network_metadata, network_error = validate_agent_network_metadata(data)

    if network_error:
        return jsonify({"error": network_error}), 400

    network = (
        network_metadata["network"]
        or g.agent.get("network")
        or "unknown"
    )

    network_cidr = (
        network_metadata["network_cidr"]
        or g.agent.get("network_cidr")
    )

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                INSERT INTO agent_upload_batches(org_id, agent_id, batch_id)
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING batch_id
                """,
                (org_id, agent_id, batch_id),
            )
            if not cur.fetchone():
                conn.rollback()
                return jsonify({"status": "duplicate_ignored", "batch_id": batch_id}), 200

            stored_count = 0
            alerts_changed = False

            for device in validated_devices:
                cur.execute(
                    """
                    SELECT trusted, times_seen, threat_count
                    FROM device_profiles
                    WHERE org_id = %s AND mac = %s
                    FOR UPDATE
                    """,
                    (org_id, device["mac"]),
                )
                profile = cur.fetchone()
                is_new_device = profile is None
                trusted = bool(profile["trusted"]) if profile else False

                risk = analyze_device(
                    device,
                    trusted=trusted,
                    expected_network_cidr=network_cidr,
                )

                cur.execute(
                    """
                    INSERT INTO devices(
                        org_id, network, ip, mac, vendor, level, score,
                        timestamp, first_seen, last_seen, last_agent_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        NOW(), NOW(), NOW(), %s
                    )
                    ON CONFLICT (org_id, mac)
                    DO UPDATE SET
                        network = EXCLUDED.network,
                        ip = EXCLUDED.ip,
                        vendor = EXCLUDED.vendor,
                        level = EXCLUDED.level,
                        score = EXCLUDED.score,
                        timestamp = NOW(),
                        last_seen = NOW(),
                        last_agent_id = EXCLUDED.last_agent_id
                    """,
                    (
                        org_id,
                        network,
                        device["ip"],
                        device["mac"],
                        device["vendor"],
                        risk["level"],
                        risk["score"],
                        agent_id,
                    ),
                )

                cur.execute(
                    """
                    INSERT INTO device_observations(
                        org_id, agent_id, network, network_cidr, ip, mac, vendor,
                        risk_level, risk_score, reasons
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        org_id,
                        agent_id,
                        network,
                        network_cidr,
                        device["ip"],
                        device["mac"],
                        device["vendor"],
                        risk["level"],
                        risk["score"],
                        Json(risk["reasons"]),
                    ),
                )

                if is_new_device:
                    cur.execute(
                        """
                        INSERT INTO device_profiles(
                            org_id, mac, vendor, trusted, trust_score,
                            threat_count, times_seen, reputation,
                            last_risk_score, last_risk_level,
                            first_seen, last_seen
                        ) VALUES (
                            %s, %s, %s, FALSE, %s, %s, 1, %s, %s, %s, NOW(), NOW()
                        )
                        """,
                        (
                            org_id,
                            device["mac"],
                            device["vendor"],
                            max(0, 100 - risk["score"]),
                            1 if risk["score"] >= 60 else 0,
                            "SUSPICIOUS" if risk["score"] >= 60 else "UNKNOWN",
                            risk["score"],
                            risk["level"],
                        ),
                    )

                    title = f"New device discovered: {device['mac']}"
                    create_event(
                        cur,
                        org_id=org_id,
                        event_type="NEW_DEVICE",
                        device=device,
                        risk=risk,
                        title=title,
                    )
                    upsert_alert(
                        cur,
                        org_id=org_id,
                        rule_key="new_device",
                        device_mac=device["mac"],
                        severity="MEDIUM",
                        title=title,
                        description=f"A previously unseen device appeared at {device['ip']}.",
                        score=max(30, risk["score"]),
                    )
                    alerts_changed = True
                else:
                    threat_count = int(profile["threat_count"] or 0) + (1 if risk["score"] >= 60 else 0)
                    times_seen = int(profile["times_seen"] or 0) + 1
                    reputation = (
                        "TRUSTED" if trusted and risk["score"] < 30
                        else "DANGEROUS" if risk["score"] >= 80
                        else "SUSPICIOUS" if risk["score"] >= 60
                        else "NORMAL"
                    )
                    cur.execute(
                        """
                        UPDATE device_profiles
                        SET vendor = %s,
                            threat_count = %s,
                            times_seen = %s,
                            trust_score = %s,
                            reputation = %s,
                            last_risk_score = %s,
                            last_risk_level = %s,
                            last_seen = NOW()
                        WHERE org_id = %s AND mac = %s
                        """,
                        (
                            device["vendor"],
                            threat_count,
                            times_seen,
                            max(0, 100 - risk["score"]),
                            reputation,
                            risk["score"],
                            risk["level"],
                            org_id,
                            device["mac"],
                        ),
                    )

                if risk["score"] >= 60:
                    title = f"High-risk device signal: {device['mac']}"
                    create_event(
                        cur,
                        org_id=org_id,
                        event_type="HIGH_RISK_DEVICE",
                        device=device,
                        risk=risk,
                        title=title,
                    )
                    upsert_alert(
                        cur,
                        org_id=org_id,
                        rule_key="high_risk_device",
                        device_mac=device["mac"],
                        severity=risk["level"],
                        title=title,
                        description="; ".join(reason["detail"] for reason in risk["reasons"]) or "Risk threshold exceeded.",
                        score=risk["score"],
                    )
                    alerts_changed = True

                stored_count += 1

            cur.execute(
                """
                UPDATE agents
                SET last_seen = NOW(), updated_at = NOW()
                WHERE agent_id = %s AND org_id = %s
                """,
                (agent_id, org_id),
            )
            conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("upload_processing_failed")
        raise

    finally:
            conn.close()


    metric_inc("uploads_total")
    metric_inc("uploaded_devices_total", len(validated_devices))

    socketio.emit("device_update", {"org_id": org_id}, to=f"org:{org_id}")
    socketio.emit("agent_update", {"agent_id": agent_id}, to=f"org:{org_id}")

    if alerts_changed:
        socketio.emit("alert_update", {"org_id": org_id}, to=f"org:{org_id}")

    return jsonify(
        {
            "status": "stored",
            "batch_id": batch_id,
            "devices_received": len(validated_devices),
            "devices_stored": stored_count,
        }
    )


# -----------------------------------------------------------------------------
# Human-facing inventory / intelligence APIs
# -----------------------------------------------------------------------------

@app.get("/devices")
@require_user()
def devices():
    device_stale_seconds = int(os.getenv("DEVICE_STALE_SECONDS", "90"))
    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT
                    ip,
                    mac,
                    vendor,
                    level,
                    score,
                    first_seen,
                    last_seen,
                    network,
                    CASE
                        WHEN last_seen >= NOW() - (%s * INTERVAL '1 second')
                            THEN 'ONLINE'
                        ELSE 'STALE'
                    END AS presence_status
                FROM devices
                WHERE org_id = %s
                ORDER BY last_seen DESC
                """,
                (device_stale_seconds, g.auth["org_id"]),
            )
            rows = cur.fetchall()

        return jsonify(
            {
                "devices": [
                    {
                        **row,
                        "first_seen": serialize_dt(row["first_seen"]),
                        "last_seen": serialize_dt(row["last_seen"]),
                    }
                    for row in rows
                ]
            }
        )
    finally:
        conn.close()


@app.get("/device-profiles")
@require_user()
def device_profiles():
    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT mac, vendor, trusted, trust_score, threat_count, times_seen,
                       reputation, last_risk_score, last_risk_level, first_seen, last_seen
                FROM device_profiles
                WHERE org_id = %s
                ORDER BY last_risk_score DESC, last_seen DESC
                """,
                (g.auth["org_id"],),
            )
            rows = cur.fetchall()
        return jsonify(
            {
                "profiles": [
                    {
                        **row,
                        "first_seen": serialize_dt(row["first_seen"]),
                        "last_seen": serialize_dt(row["last_seen"]),
                    }
                    for row in rows
                ]
            }
        )
    finally:
        conn.close()


@app.patch("/device-profiles/<path:mac>/trust")
@require_user(roles={"OWNER", "ADMIN"})
def set_device_trust(mac: str):
    data = request.get_json(silent=True) or {}
    trusted = parse_bool(data.get("trusted"))
    if trusted is None:
        return jsonify({"error": "trusted must be true or false"}), 400

    normalized_mac = normalize_mac(mac)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE device_profiles
                SET trusted = %s,
                    reputation = CASE WHEN %s THEN 'TRUSTED' ELSE 'UNKNOWN' END
                WHERE org_id = %s AND mac = %s
                RETURNING id
                """,
                (trusted, trusted, g.auth["org_id"], normalized_mac),
            )
            updated = cur.fetchone()
        conn.commit()
        if not updated:
            return jsonify({"error": "Device profile not found"}), 404
        return jsonify({"mac": normalized_mac, "trusted": trusted})
    finally:
        conn.close()


@app.get("/agents")
@require_user()
def agents():
    stale_seconds = int(os.getenv("AGENT_STALE_SECONDS", "60"))
    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT agent_id, network, network_cidr, last_seen, status,
                       CASE
                           WHEN status <> 'ACTIVE' THEN status
                           WHEN last_seen IS NULL THEN 'NEVER_SEEN'
                           WHEN last_seen < NOW() - (%s * INTERVAL '1 second') THEN 'STALE'
                           ELSE 'ACTIVE'
                       END AS health_status
                FROM agents
                WHERE org_id = %s
                ORDER BY last_seen DESC NULLS LAST
                """,
                (stale_seconds, g.auth["org_id"]),
            )
            rows = cur.fetchall()

        return jsonify(
            {
                "agents": [
                    {**row, "last_seen": serialize_dt(row["last_seen"])}
                    for row in rows
                ]
            }
        )
    finally:
        conn.close()


def dashboard_summary_payload(org_id: str) -> dict[str, Any]:
    stale_seconds = int(os.getenv("AGENT_STALE_SECONDS", "60"))
    device_stale_seconds = int(os.getenv("DEVICE_STALE_SECONDS", "90"))

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS known_devices,

                    COUNT(*) FILTER (
                        WHERE last_seen >= NOW() - (%s * INTERVAL '1 second')
                    ) AS online_devices,

                    COUNT(*) FILTER (
                        WHERE last_seen < NOW() - (%s * INTERVAL '1 second')
                    ) AS stale_devices,

                    COALESCE(
                        AVG(score) FILTER (
                            WHERE last_seen >= NOW() - (%s * INTERVAL '1 second')
                        ),
                        0
                    ) AS avg_risk,

                    COUNT(*) FILTER (
                        WHERE score >= 60
                            AND last_seen >= NOW() - (%s * INTERVAL '1 second')
                    ) AS high_risk_devices,

                    MAX(last_seen) AS last_device_seen

                FROM devices
                WHERE org_id = %s
                """,
                (
                    device_stale_seconds,
                    device_stale_seconds,
                    device_stale_seconds,
                    device_stale_seconds,
                    org_id,
                ),
            )

            base = cur.fetchone()

            cur.execute(
                """
                SELECT level, COUNT(*) AS count
                FROM devices
                WHERE org_id = %s
                    AND last_seen >= NOW() - (%s * INTERVAL '1 second')
                GROUP BY level
                """,
                (org_id, device_stale_seconds),
            )
            distribution_rows = cur.fetchall()

            cur.execute(
                """
                SELECT date_trunc('minute', observed_at) AS bucket,
                       ROUND(AVG(risk_score)::numeric, 2) AS avg_risk
                FROM device_observations
                WHERE org_id = %s
                  AND observed_at >= NOW() - INTERVAL '60 minutes'
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (org_id,),
            )
            trend_rows = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(*) AS total_agents,
                       COUNT(*) FILTER (
                           WHERE status = 'ACTIVE'
                             AND last_seen >= NOW() - (%s * INTERVAL '1 second')
                       ) AS active_agents,
                       COUNT(*) FILTER (
                           WHERE status = 'ACTIVE'
                             AND (last_seen IS NULL OR last_seen < NOW() - (%s * INTERVAL '1 second'))
                       ) AS stale_agents
                FROM agents
                WHERE org_id = %s
                """,
                (stale_seconds, stale_seconds, org_id),
            )
            agent_counts = cur.fetchone()

            cur.execute(
                """
                SELECT COUNT(*) AS open_alerts
                FROM alerts
                WHERE org_id = %s AND status IN ('OPEN', 'ACKNOWLEDGED')
                """,
                (org_id,),
            )
            open_alerts = cur.fetchone()["open_alerts"]

            cur.execute(
                """
                SELECT mac, ip, vendor, score, level, last_seen
                FROM devices
                WHERE org_id = %s
                    AND last_seen >= NOW() - (%s * INTERVAL '1 second')
                ORDER BY score DESC, last_seen DESC
                LIMIT 10
                """,
                (org_id, device_stale_seconds),
            )
            risky_devices = cur.fetchall()

        total_agents = int(agent_counts["total_agents"] or 0)
        active_agents = int(agent_counts["active_agents"] or 0)
        high_risk = int(base["high_risk_devices"] or 0)

        if total_agents == 0:
            system_status = "NO_AGENTS"
        elif active_agents == 0:
            system_status = "COLLECTORS_STALE"
        elif high_risk > 0 or int(open_alerts or 0) > 0:
            system_status = "ATTENTION"
        else:
            system_status = "MONITORING"

        distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for row in distribution_rows:
            key = row["level"] or "LOW"
            if key in distribution:
                distribution[key] = int(row["count"])

        return {
            "device_count": int(base["known_devices"] or 0),
            "known_devices": int(base["known_devices"] or 0),
            "online_devices": int(base["online_devices"] or 0),
            "stale_devices": int(base["stale_devices"] or 0),
            "avg_risk": round(float(base["avg_risk"] or 0), 2),
            "high_risk_devices": high_risk,
            "dangerous_devices": high_risk,
            "open_alerts": int(open_alerts or 0),
            "unresolved_alerts": int(open_alerts or 0),
            "total_agents": total_agents,
            "active_agents": active_agents,
            "stale_agents": int(agent_counts["stale_agents"] or 0),
            "system_status": system_status,
            "last_device_seen": serialize_dt(base["last_device_seen"]),
            "risk_distribution": [
                {"name": level, "value": count}
                for level, count in distribution.items()
            ],
            "risk_trend": [
                {"time": serialize_dt(row["bucket"]), "risk": float(row["avg_risk"])}
                for row in trend_rows
            ],
            "risky_devices": [
                {**row, "last_seen": serialize_dt(row["last_seen"])}
                for row in risky_devices
            ],
        }
    finally:
        conn.close()


@app.get("/dashboard/summary")
@require_user()
def dashboard_summary():
    return jsonify(dashboard_summary_payload(g.auth["org_id"]))


@app.get("/intelligence")
@require_user()
def intelligence():
    # Backward-compatible endpoint name. The payload is intentionally based on
    # measured device/observation data; it does not claim ML inference.
    return jsonify(dashboard_summary_payload(g.auth["org_id"]))


# -----------------------------------------------------------------------------
# Event / alert workflow
# -----------------------------------------------------------------------------

@app.get("/events")
@require_user()
def list_events():
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """
                SELECT id, event_type, device_mac, device_ip, severity,
                       score, title, evidence, observed_at
                FROM security_events
                WHERE org_id = %s
                ORDER BY observed_at DESC
                LIMIT %s
                """,
                (g.auth["org_id"], limit),
            )
            rows = cur.fetchall()
        return jsonify(
            {
                "events": [
                    {**row, "observed_at": serialize_dt(row["observed_at"])}
                    for row in rows
                ]
            }
        )
    finally:
        conn.close()


@app.get("/alerts")
@require_user()
def list_alerts():
    status = str(request.args.get("status") or "").upper()
    params: list[Any] = [g.auth["org_id"]]
    status_sql = ""
    if status in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        status_sql = " AND status = %s"
        params.append(status)

    conn = get_db()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                f"""
                SELECT id, rule_key, device_mac, severity, status, title,
                       description, score, first_seen, last_seen, occurrences,
                       acknowledged_at, acknowledged_by, resolved_at, resolved_by
                FROM alerts
                WHERE org_id = %s {status_sql}
                ORDER BY
                    CASE status WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END,
                    last_seen DESC
                LIMIT 500
                """,
                tuple(params),
            )
            rows = cur.fetchall()

        date_fields = {"first_seen", "last_seen", "acknowledged_at", "resolved_at"}
        serialized = []
        for row in rows:
            item = dict(row)
            for field in date_fields:
                item[field] = serialize_dt(item[field])
            serialized.append(item)
        return jsonify({"alerts": serialized})
    finally:
        conn.close()


def transition_alert(alert_id: int, new_status: str):
    user_field = "acknowledged_by" if new_status == "ACKNOWLEDGED" else "resolved_by"
    time_field = "acknowledged_at" if new_status == "ACKNOWLEDGED" else "resolved_at"

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE alerts
                SET status = %s,
                    {user_field} = %s,
                    {time_field} = NOW()
                WHERE id = %s AND org_id = %s
                RETURNING id
                """,
                (new_status, g.auth["user_id"], alert_id, g.auth["org_id"]),
            )
            updated = cur.fetchone()
        conn.commit()
        if not updated:
            return jsonify({"error": "Alert not found"}), 404

        socketio.emit("alert_update", {"org_id": g.auth["org_id"]}, to=f"org:{g.auth['org_id']}")
        return jsonify({"id": alert_id, "status": new_status})
    finally:
        conn.close()


@app.post("/alerts/<int:alert_id>/acknowledge")
@require_user(roles={"OWNER", "ADMIN", "OPERATOR"})
def acknowledge_alert(alert_id: int):
    return transition_alert(alert_id, "ACKNOWLEDGED")


@app.post("/alerts/<int:alert_id>/resolve")
@require_user(roles={"OWNER", "ADMIN", "OPERATOR"})
def resolve_alert(alert_id: int):
    return transition_alert(alert_id, "RESOLVED")


# -----------------------------------------------------------------------------
# Authenticated WebSocket rooms prevent cross-tenant event leakage
# -----------------------------------------------------------------------------

@socketio.on("connect")
def socket_connect(auth):
    auth = auth or {}
    token = str(auth.get("token") or "")
    org_id = normalize_org_id(auth.get("org_id"))
    if not token or not org_id:
        return False

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM auth_sessions s
                JOIN org_memberships m ON m.user_id = s.user_id
                WHERE s.token_hash = %s
                  AND s.expires_at > NOW()
                  AND m.org_id = %s
                """,
                (hash_token(token), org_id),
            )
            if not cur.fetchone():
                return False
    finally:
        conn.close()

    join_room(f"org:{org_id}")
    return True


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    logger.info("server_starting", extra={"fields": {"port": port}})
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)
