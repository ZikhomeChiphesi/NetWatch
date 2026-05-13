import os
import functools
import uuid
import secrets
from datetime import datetime, timedelta

import psycopg2
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv

from threat_engine import analyze_device

load_dotenv("../.env")

# =========================
# APP
# =========================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "netwatch_dev")

socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE_URL = os.getenv("DATABASE_URL")


# =========================
# DB
# =========================
def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")


# =========================
# MAC VENDOR LOOKUP
# =========================
def get_vendor(mac):

    if not mac:
        return "Unknown"

    prefixes = {
        "00:1A": "Cisco",
        "3C:52": "Apple",
        "B8:27": "Raspberry Pi",
        "FC:FB": "Samsung",
        "D8:3A": "Intel",
        "A4:5E": "Google"
    }

    for prefix, vendor in prefixes.items():
        if mac.upper().startswith(prefix):
            return vendor

    return "Unknown Vendor"


# =========================
# INIT TABLES
# =========================
def init_tables():

    conn = get_db()
    cur = conn.cursor()

    # ---------------------
    # DEVICES
    # ---------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id SERIAL PRIMARY KEY,
            network TEXT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            level TEXT,
            score INTEGER,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    # ---------------------
    # AGENTS
    # ---------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id SERIAL PRIMARY KEY,
            agent_id TEXT UNIQUE,
            api_key TEXT,
            network TEXT,
            last_seen TIMESTAMP DEFAULT NOW()
        )
    """)

    # ---------------------
    # HEARTBEATS
    # ---------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id SERIAL PRIMARY KEY,
            agent_id TEXT,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    # ---------------------
    # DEVICE PROFILES
    # ---------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_profiles (
            id SERIAL PRIMARY KEY,
            mac TEXT UNIQUE,
            vendor TEXT,
            trust_score INTEGER DEFAULT 50,
            threat_count INTEGER DEFAULT 0,
            times_seen INTEGER DEFAULT 1,
            reputation TEXT DEFAULT 'UNKNOWN',
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW()
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


# =========================
# AUTH
# =========================
def require_api_key(f):

    @functools.wraps(f)
    def wrapper(*args, **kwargs):

        key = request.headers.get("X-API-Key", "")

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT agent_id FROM agents WHERE api_key = %s",
            (key,)
        )

        result = cur.fetchone()

        cur.close()
        conn.close()

        if not result:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)

    return wrapper


# =========================
# REGISTER AGENT
# =========================
@app.route("/register", methods=["POST"])
def register_agent():

    data = request.json or {}
    network = data.get("network", "unknown")

    agent_id = str(uuid.uuid4())
    api_key = secrets.token_hex(16)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO agents (
            agent_id,
            api_key,
            network
        )
        VALUES (%s, %s, %s)
    """, (agent_id, api_key, network))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "agent_id": agent_id,
        "api_key": api_key
    })


# =========================
# HEARTBEAT
# =========================
@app.route("/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():

    key = request.headers.get("X-API-Key")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT agent_id FROM agents WHERE api_key = %s",
        (key,)
    )

    row = cur.fetchone()

    if not row:
        return jsonify({"error": "unknown agent"}), 401

    agent_id = row[0]

    cur.execute("""
        INSERT INTO heartbeats (agent_id)
        VALUES (%s)
    """, (agent_id,))

    cur.execute("""
        UPDATE agents
        SET last_seen = NOW()
        WHERE agent_id = %s
    """, (agent_id,))

    conn.commit()
    cur.close()
    conn.close()

    socketio.emit("agent_update", {
        "agent_id": agent_id,
        "status": "online"
    })

    return jsonify({"status": "alive"})


# =========================
# DEVICE MEMORY ENGINE
# =========================
def update_device_profile(cur, mac, vendor, score):

    cur.execute("""
        SELECT trust_score, threat_count, times_seen
        FROM device_profiles
        WHERE mac = %s
    """, (mac,))

    existing = cur.fetchone()

    # ---------------------
    # NEW DEVICE
    # ---------------------
    if not existing:

        reputation = "SUSPICIOUS" if score >= 70 else "UNKNOWN"

        trust_score = max(5, 100 - score)

        cur.execute("""
            INSERT INTO device_profiles (
                mac,
                vendor,
                trust_score,
                threat_count,
                times_seen,
                reputation
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            mac,
            vendor,
            trust_score,
            1 if score >= 70 else 0,
            1,
            reputation
        ))

        return

    # ---------------------
    # EXISTING DEVICE
    # ---------------------
    trust_score, threat_count, times_seen = existing

    times_seen += 1

    if score >= 70:
        threat_count += 1
        trust_score -= 10
    else:
        trust_score += 1

    trust_score = max(0, min(100, trust_score))

    # reputation logic
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
            last_seen = NOW()
        WHERE mac = %s
    """, (
        trust_score,
        threat_count,
        times_seen,
        reputation,
        mac
    ))


# =========================
# DEVICE UPLOAD
# =========================
@app.route("/upload", methods=["POST"])
@require_api_key
def upload_data():

    data = request.json or {}

    network = data.get("network", "unknown")
    devices = data.get("devices", [])

    conn = get_db()
    cur = conn.cursor()

    for d in devices:

        analyzed = analyze_device(d, devices)

        vendor = get_vendor(analyzed["mac"])

        # ---------------------
        # STORE DEVICE EVENT
        # ---------------------
        cur.execute("""
            INSERT INTO devices (
                network,
                ip,
                mac,
                vendor,
                level,
                score
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            network,
            analyzed["ip"],
            analyzed["mac"],
            vendor,
            analyzed["level"],
            analyzed["score"]
        ))

        # ---------------------
        # UPDATE REPUTATION MEMORY
        # ---------------------
        update_device_profile(
            cur,
            analyzed["mac"],
            vendor,
            analyzed["score"]
        )

    conn.commit()
    cur.close()
    conn.close()

    socketio.emit("device_update", {
        "network": network
    })

    return jsonify({"status": "stored"})


# =========================
# AGENTS
# =========================
@app.route("/agents", methods=["GET"])
def get_agents():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT agent_id, network, last_seen
        FROM agents
    """)

    rows = cur.fetchall()

    now = datetime.utcnow()

    agents = []

    for r in rows:

        last_seen = r[2]

        status = (
            "ONLINE"
            if (now - last_seen) < timedelta(seconds=30)
            else "OFFLINE"
        )

        agents.append({
            "agent_id": r[0],
            "network": r[1],
            "last_seen": str(last_seen),
            "status": status
        })

    cur.close()
    conn.close()

    return jsonify(agents)


# =========================
# DEVICE PROFILES
# =========================
@app.route("/profiles", methods=["GET"])
def get_profiles():

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
        ORDER BY trust_score ASC
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    profiles = []

    for r in rows:
        profiles.append({
            "mac": r[0],
            "vendor": r[1],
            "trust_score": r[2],
            "threat_count": r[3],
            "times_seen": r[4],
            "reputation": r[5],
            "first_seen": str(r[6]),
            "last_seen": str(r[7])
        })

    return jsonify(profiles)


# =========================
# INTELLIGENCE
# =========================
@app.route("/intelligence", methods=["GET"])
def intelligence():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    device_count = cur.fetchone()[0]

    cur.execute("SELECT AVG(score) FROM devices")
    avg_risk = cur.fetchone()[0] or 0

    cur.execute("""
        SELECT COUNT(*)
        FROM device_profiles
        WHERE reputation = 'DANGEROUS'
    """)

    dangerous_devices = cur.fetchone()[0]

    cur.execute("""
        SELECT mac, trust_score, reputation
        FROM device_profiles
        ORDER BY trust_score ASC
        LIMIT 10
    """)

    risky = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({
        "device_count": device_count,
        "avg_risk": float(avg_risk),
        "dangerous_devices": dangerous_devices,
        "risky_devices": [
            {
                "mac": r[0],
                "trust_score": r[1],
                "reputation": r[2]
            }
            for r in risky
        ]
    })


# =========================
# HEALTH
# =========================
@app.route("/")
def home():

    return jsonify({
        "status": "NetWatch Threat Intelligence Active",
        "phase": "9.3",
        "features": [
            "device memory",
            "reputation engine",
            "threat scoring",
            "persistent profiles"
        ]
    })


# =========================
# START
# =========================
if __name__ == "__main__":

    init_tables()

    port = int(os.environ.get("PORT", 5000))

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False
    )