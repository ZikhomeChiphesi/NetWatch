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
# APP SETUP
# =========================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "netwatch_dev_key")

socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE_URL = os.getenv("DATABASE_URL")


# =========================
# DB CONNECTION
# =========================
def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")


# =========================
# INIT TABLES
# =========================
def init_tables():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id SERIAL PRIMARY KEY,
            network TEXT,
            ip TEXT,
            mac TEXT,
            level TEXT,
            score INTEGER,
            is_new BOOLEAN DEFAULT FALSE,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id SERIAL PRIMARY KEY,
            agent_id TEXT UNIQUE,
            api_key TEXT,
            network TEXT,
            last_seen TIMESTAMP DEFAULT NOW()
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS heartbeats (
            id SERIAL PRIMARY KEY,
            agent_id TEXT,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


# =========================
# AUTH MIDDLEWARE
# =========================
def require_api_key(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT agent_id FROM agents WHERE api_key = %s", (key,))
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
        INSERT INTO agents (agent_id, api_key, network)
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

    cur.execute("SELECT agent_id FROM agents WHERE api_key = %s", (key,))
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
# DEVICE UPLOAD + PHASE 9 INTELLIGENCE
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

        cur.execute("""
            INSERT INTO devices (
                network, ip, mac, level, score, is_new
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            network,
            analyzed["ip"],
            analyzed["mac"],
            analyzed["level"],
            analyzed["score"],
            analyzed.get("is_new", False)
        ))

    conn.commit()
    cur.close()
    conn.close()

    # real-time push
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
        status = "ONLINE" if (now - last_seen) < timedelta(seconds=30) else "OFFLINE"

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
# DEVICES
# =========================
@app.route("/devices", methods=["GET"])
def get_devices():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT ip, mac, level, score, is_new
        FROM devices
        ORDER BY timestamp DESC
        LIMIT 200
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify([
        {
            "ip": r[0],
            "mac": r[1],
            "level": r[2],
            "score": r[3],
            "is_new": r[4]
        }
        for r in rows
    ])


# =========================
# INTELLIGENCE ENDPOINT (FOR REACT DASHBOARD)
# =========================
@app.route("/intelligence", methods=["GET"])
def intelligence():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM devices")
    device_count = cur.fetchone()[0]

    cur.execute("SELECT AVG(score) FROM devices")
    avg_risk = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM devices WHERE level = 'HIGH'")
    high_threats = cur.fetchone()[0]

    cur.execute("""
        SELECT ip, mac, score
        FROM devices
        WHERE is_new = TRUE
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    anomalies = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({
        "device_count": device_count,
        "avg_risk": float(avg_risk),
        "high_threats": high_threats,
        "anomalies": [
            {"ip": a[0], "mac": a[1], "score": a[2]}
            for a in anomalies
        ]
    })


# =========================
# HEALTH CHECK
# =========================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "NetWatch Phase 9 Backend Running",
        "features": [
            "device intelligence",
            "anomaly scoring",
            "real-time sockets",
            "agent tracking"
        ]
    })


# =========================
# START SERVER
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