import os
import functools
import uuid
import secrets
from datetime import datetime, timedelta

import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from dotenv import load_dotenv
from pathlib import Path

from threat_engine import analyze_device


# ============================================================
# ENVIRONMENT
# ============================================================


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "netwatch_dev"
)

CORS(
    app,
    origins=["http://localhost:5173"]
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)


# ============================================================
# DATABASE
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL")


def get_db():
    """
    Connect to PostgreSQL.

    Local development uses DB_PASSWORD from .env.
    If DATABASE_URL is provided, it is used instead.
    """

    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)

    return psycopg2.connect(
        host="localhost",
        port=5432,
        database="netwatch",
        user="postgres",
        password=os.getenv("DB_PASSWORD")
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_tables():

    conn = get_db()
    cur = conn.cursor()

    # --------------------------------------------------------
    # ORGANIZATIONS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id SERIAL PRIMARY KEY,
            org_id TEXT UNIQUE,
            name TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            user_id TEXT UNIQUE,
            org_id TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)

    # --------------------------------------------------------
    # AGENTS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id SERIAL PRIMARY KEY,
            agent_id TEXT UNIQUE,
            api_key TEXT UNIQUE,
            org_id TEXT,
            network TEXT,
            last_seen TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # HEARTBEATS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id SERIAL PRIMARY KEY,
            agent_id TEXT,
            org_id TEXT,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    # --------------------------------------------------------
    # DEVICES
    #
    # This table stores historical observations.
    # A new row can be created every time the scanner sees
    # a device. This gives NetWatch historical data for
    # future analytics and AI.
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id SERIAL PRIMARY KEY,
            org_id TEXT,
            network TEXT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            level TEXT,
            score INTEGER,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    # --------------------------------------------------------
    # DEVICE PROFILES
    #
    # One persistent profile per organization + MAC address.
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_profiles (
            id SERIAL PRIMARY KEY,
            org_id TEXT,
            mac TEXT,
            vendor TEXT,
            trust_score INTEGER DEFAULT 50,
            threat_count INTEGER DEFAULT 0,
            times_seen INTEGER DEFAULT 1,
            reputation TEXT DEFAULT 'UNKNOWN',
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW(),

            UNIQUE(org_id, mac)
        )
    """)

    conn.commit()

    cur.close()
    conn.close()

    print("[DATABASE] Tables initialized successfully")


# ============================================================
# HELPERS
# ============================================================

def get_org_id():
    """
    Get organization ID from request header.
    """

    return request.headers.get("X-ORG-ID")


def get_vendor(mac):
    """
    Basic vendor lookup placeholder.

    The scanner currently provides MAC addresses.
    A future version can connect this to a proper
    MAC vendor database/API.
    """

    return "Unknown"


# ============================================================
# ORGANIZATION AUTHENTICATION
# ============================================================

def require_org(function):

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        org_id = get_org_id()

        if not org_id:
            return jsonify({
                "error": "Missing X-ORG-ID"
            }), 401

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# AGENT API-KEY AUTHENTICATION
# ============================================================

def require_api_key(function):

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        api_key = request.headers.get("X-API-Key")
        org_id = request.headers.get("X-ORG-ID")

        if not api_key:
            return jsonify({
                "error": "Missing X-API-Key"
            }), 401

        if not org_id:
            return jsonify({
                "error": "Missing X-ORG-ID"
            }), 401

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT agent_id
            FROM agents
            WHERE api_key = %s
              AND org_id = %s
        """, (
            api_key,
            org_id
        ))

        row = cur.fetchone()

        cur.close()
        conn.close()

        if not row:
            return jsonify({
                "error": "Unauthorized agent"
            }), 401

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "name": "NetWatch API",
        "status": "online",
        "version": "1.0"
    })


@app.route("/health", methods=["GET"])
def health():

    try:

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT 1")

        cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            "status": "healthy",
            "database": "connected"
        })

    except Exception as e:

        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }), 500


# ============================================================
# REGISTER AGENT
# ============================================================

@app.route("/register", methods=["POST"])
def register_agent():

    data = request.json or {}

    network = data.get(
        "network",
        "unknown"
    )

    org_id = data.get("org_id")

    if not org_id:

        return jsonify({
            "error": "org_id required"
        }), 400

    agent_id = str(uuid.uuid4())

    api_key = secrets.token_hex(16)

    conn = get_db()
    cur = conn.cursor()

    # Ensure organization exists
    cur.execute("""
        INSERT INTO organizations
            (org_id, name)
        VALUES
            (%s, %s)
        ON CONFLICT (org_id)
        DO NOTHING
    """, (
        org_id,
        org_id
    ))

    cur.execute("""
        INSERT INTO agents
            (agent_id, api_key, org_id, network)
        VALUES
            (%s, %s, %s, %s)
    """, (
        agent_id,
        api_key,
        org_id,
        network
    ))

    conn.commit()

    cur.close()
    conn.close()

    print(
        f"[REGISTER] Agent registered: "
        f"{agent_id} | Org: {org_id}"
    )

    return jsonify({
        "agent_id": agent_id,
        "api_key": api_key,
        "org_id": org_id
    })


# ============================================================
# HEARTBEAT
# ============================================================

@app.route("/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():

    key = request.headers.get("X-API-Key")
    org_id = request.headers.get("X-ORG-ID")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT agent_id
        FROM agents
        WHERE api_key = %s
          AND org_id = %s
    """, (
        key,
        org_id
    ))

    row = cur.fetchone()

    if not row:

        cur.close()
        conn.close()

        return jsonify({
            "error": "unknown agent"
        }), 401

    agent_id = row[0]

    cur.execute("""
        INSERT INTO heartbeats
            (agent_id, org_id)
        VALUES
            (%s, %s)
    """, (
        agent_id,
        org_id
    ))

    cur.execute("""
        UPDATE agents
        SET last_seen = NOW()
        WHERE agent_id = %s
          AND org_id = %s
    """, (
        agent_id,
        org_id
    ))

    conn.commit()

    cur.close()
    conn.close()

    socketio.emit(
        "agent_update",
        {
            "agent_id": agent_id,
            "org_id": org_id
        }
    )

    return jsonify({
        "status": "alive"
    })


# ============================================================
# UPLOAD SCAN DATA
# ============================================================

@app.route("/upload", methods=["POST"])
@require_api_key
def upload_data():

    data = request.json or {}

    org_id = request.headers.get("X-ORG-ID")

    network = data.get(
        "network",
        "unknown"
    )

    devices = data.get(
        "devices",
        []
    )

    if not isinstance(devices, list):

        return jsonify({
            "error": "devices must be a list"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    stored_count = 0

    for device in devices:

        try:

            # ------------------------------------------------
            # AI / THREAT ANALYSIS
            # ------------------------------------------------

            analyzed = analyze_device(device)

            mac = analyzed.get(
                "mac",
                device.get("mac", "unknown")
            )

            ip = analyzed.get(
                "ip",
                device.get("ip", "unknown")
            )

            level = analyzed.get(
                "level",
                "LOW"
            )

            score = analyzed.get(
                "score",
                0
            )

            vendor = get_vendor(mac)


            # ------------------------------------------------
            # UPDATE CURRENT DEVICE STATE
            #
            # One row per organization + MAC.
            # Every scan updates the existing device instead
            # of creating another historical row.
            # ------------------------------------------------

            cur.execute("""
                INSERT INTO devices
                    (
                        org_id,
                        network,
                        ip,
                        mac,
                        vendor,
                        level,
                        score,
                        timestamp
                    )
                VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        NOW()
                    )
                ON CONFLICT (org_id, mac)
                DO UPDATE SET
                    network = EXCLUDED.network,
                    ip = EXCLUDED.ip,
                    vendor = EXCLUDED.vendor,
                    level = EXCLUDED.level,
                    score = EXCLUDED.score,
                    timestamp = NOW()
            """, (
                org_id,
                network,
                ip,
                mac,
                vendor,
                level,
                score
            ))

            # ------------------------------------------------
            # GET EXISTING DEVICE PROFILE
            # ------------------------------------------------

            cur.execute("""
                SELECT
                    trust_score,
                    threat_count,
                    times_seen
                FROM device_profiles
                WHERE org_id = %s
                  AND mac = %s
            """, (
                org_id,
                mac
            ))

            existing = cur.fetchone()

            # ------------------------------------------------
            # NEW DEVICE
            # ------------------------------------------------

            if not existing:

                initial_trust = 50

                initial_threats = (
                    1
                    if score >= 70
                    else 0
                )

                initial_reputation = (
                    "SUSPICIOUS"
                    if score >= 70
                    else "UNKNOWN"
                )

                cur.execute("""
                    INSERT INTO device_profiles
                    (
                        org_id,
                        mac,
                        vendor,
                        trust_score,
                        threat_count,
                        times_seen,
                        reputation
                    )
                    VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                """, (
                    org_id,
                    mac,
                    vendor,
                    initial_trust,
                    initial_threats,
                    1,
                    initial_reputation
                ))

            # ------------------------------------------------
            # EXISTING DEVICE
            # ------------------------------------------------

            else:

                trust_score, threat_count, times_seen = existing

                times_seen += 1

                if score >= 70:

                    threat_count += 1

                    trust_score -= 10

                else:

                    trust_score += 1

                # Keep trust score between 0 and 100
                trust_score = max(
                    0,
                    min(100, trust_score)
                )

                # Determine reputation
                if trust_score >= 80:

                    reputation = "TRUSTED"

                elif trust_score >= 50:

                    reputation = "NORMAL"

                elif trust_score >= 25:

                    reputation = "SUSPICIOUS"

                else:

                    reputation = "DANGEROUS"

                cur.execute("""
                    UPDATE device_profiles
                    SET
                        trust_score = %s,
                        threat_count = %s,
                        times_seen = %s,
                        reputation = %s,
                        vendor = %s,
                        last_seen = NOW()
                    WHERE org_id = %s
                      AND mac = %s
                """, (
                    trust_score,
                    threat_count,
                    times_seen,
                    reputation,
                    vendor,
                    org_id,
                    mac
                ))

            stored_count += 1

        except Exception as e:

            print(
                "[UPLOAD] Device processing error:",
                e
            )

    conn.commit()

    cur.close()
    conn.close()

    # Notify connected dashboards
    socketio.emit(
        "device_update",
        {
            "org_id": org_id
        }
    )

    return jsonify({
        "status": "stored",
        "devices_received": len(devices),
        "devices_stored": stored_count
    })


# ============================================================
# NETWORK INTELLIGENCE
# ============================================================

@app.route("/intelligence", methods=["GET"])
@require_org
def intelligence():

    org_id = get_org_id()

    conn = get_db()
    cur = conn.cursor()

    # --------------------------------------------------------
    # CURRENT DEVICE COUNT
    #
    # The devices table contains historical observations.
    # We therefore select only the newest row for each MAC.
    # --------------------------------------------------------

    cur.execute("""
        SELECT COUNT(*)
        FROM devices d
        WHERE d.org_id = %s
          AND d.id IN (
              SELECT MAX(id)
              FROM devices
              WHERE org_id = %s
              GROUP BY mac
          )
    """, (
        org_id,
        org_id
    ))

    device_count = cur.fetchone()[0]

    # --------------------------------------------------------
    # CURRENT AVERAGE RISK
    # --------------------------------------------------------

    cur.execute("""
        SELECT AVG(d.score)
        FROM devices d
        WHERE d.org_id = %s
          AND d.id IN (
              SELECT MAX(id)
              FROM devices
              WHERE org_id = %s
              GROUP BY mac
          )
    """, (
        org_id,
        org_id
    ))

    avg_risk = cur.fetchone()[0]

    if avg_risk is None:
        avg_risk = 0

    # --------------------------------------------------------
    # DANGEROUS DEVICES
    # --------------------------------------------------------

    cur.execute("""
        SELECT COUNT(*)
        FROM device_profiles
        WHERE org_id = %s
          AND reputation = 'DANGEROUS'
    """, (
        org_id,
    ))

    dangerous = cur.fetchone()[0]

    # --------------------------------------------------------
    # RISKIEST DEVICES
    # --------------------------------------------------------

    cur.execute("""
        SELECT
            mac,
            trust_score,
            reputation
        FROM device_profiles
        WHERE org_id = %s
        ORDER BY trust_score ASC
        LIMIT 10
    """, (
        org_id,
    ))

    risky = cur.fetchall()

    # --------------------------------------------------------
    # CURRENT AGENTS
    # --------------------------------------------------------

    cur.execute("""
        SELECT
            agent_id,
            network,
            last_seen
        FROM agents
        WHERE org_id = %s
        ORDER BY last_seen DESC NULLS LAST
    """, (
        org_id,
    ))

    agents = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({

        "device_count": device_count,

        "avg_risk": round(
            float(avg_risk),
            2
        ),

        "dangerous_devices": dangerous,

        "risky_devices": [
            {
                "mac": row[0],
                "trust_score": row[1],
                "reputation": row[2]
            }
            for row in risky
        ],

        "agents": [
            {
                "agent_id": row[0],
                "network": row[1],
                "last_seen": (
                    row[2].isoformat()
                    if row[2]
                    else None
                )
            }
            for row in agents
        ]
    })


# ============================================================
# DEVICE HISTORY
# ============================================================

@app.route("/devices", methods=["GET"])
@require_org
def devices():

    org_id = get_org_id()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            d.ip,
            d.mac,
            d.vendor,
            d.level,
            d.score,
            d.timestamp
        FROM devices d
        WHERE d.org_id = %s
          AND d.id IN (
              SELECT MAX(id)
              FROM devices
              WHERE org_id = %s
              GROUP BY mac
          )
        ORDER BY d.score DESC, d.timestamp DESC
    """, (
        org_id,
        org_id
    ))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({

        "devices": [

            {
                "ip": row[0],
                "mac": row[1],
                "vendor": row[2],
                "level": row[3],
                "score": row[4],
                "timestamp": (
                    row[5].isoformat()
                    if row[5]
                    else None
                )
            }

            for row in rows
        ]
    })


# ============================================================
# DEVICE PROFILES
# ============================================================

@app.route("/device-profiles", methods=["GET"])
@require_org
def device_profiles():

    org_id = get_org_id()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            mac,
            vendor,
            trust_score,
            threat_count,
            times_seen,
            reputation,
            first_seen,
            last_seen
        FROM device_profiles
        WHERE org_id = %s
        ORDER BY trust_score ASC
    """, (
        org_id,
    ))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({

        "profiles": [

            {
                "mac": row[0],
                "vendor": row[1],
                "trust_score": row[2],
                "threat_count": row[3],
                "times_seen": row[4],
                "reputation": row[5],
                "first_seen": (
                    row[6].isoformat()
                    if row[6]
                    else None
                ),
                "last_seen": (
                    row[7].isoformat()
                    if row[7]
                    else None
                )
            }

            for row in rows
        ]
    })


# ============================================================
# AGENT STATUS
# ============================================================

@app.route("/agents", methods=["GET"])
@require_org
def agents():

    org_id = get_org_id()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            agent_id,
            network,
            last_seen
        FROM agents
        WHERE org_id = %s
        ORDER BY last_seen DESC NULLS LAST
    """, (
        org_id,
    ))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({

        "agents": [

            {
                "agent_id": row[0],
                "network": row[1],
                "last_seen": (
                    row[2].isoformat()
                    if row[2]
                    else None
                )
            }

            for row in rows
        ]
    })


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print("")
    print("========================================")
    print("        NETWATCH SECURITY API")
    print("========================================")
    print("")

    init_tables()

    print("[SERVER] Starting NetWatch API...")
    print("[SERVER] Host: 0.0.0.0")
    print("[SERVER] Port:", os.environ.get("PORT", 5000))
    print("")

    socketio.run(
        app,
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False,
        use_reloader=False
    )