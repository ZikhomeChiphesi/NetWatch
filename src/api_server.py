import os
import functools
import uuid
import secrets
import threading
import time
from datetime import datetime, timedelta

import psycopg2
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv

load_dotenv("../.env")

# =========================
# APP
# =========================
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE_URL = os.getenv("DATABASE_URL")


# =========================
# DB
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
# AUTH
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
# RISK SCORING ENGINE (INTELLIGENCE CORE)
# =========================
def calculate_risk(device):
    score = 0

    level = device.get("level", "LOW")

    if level == "HIGH":
        score += 60
    elif level == "MEDIUM":
        score += 30
    else:
        score += 10

    mac = device.get("mac", "")
    if mac and len(mac.split(":")) < 6:
        score += 20

    return min(score, 100)


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
        UPDATE agents
        SET last_seen = NOW()
        WHERE agent_id = %s
    """, (agent_id,))

    conn.commit()
    cur.close()
    conn.close()

    socketio.emit("agent_status", {
        "agent_id": agent_id,
        "status": "online"
    })

    return jsonify({"status": "alive"})


# =========================
# DEVICE UPLOAD + INTELLIGENCE
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
        risk = calculate_risk(d)

        cur.execute("""
            INSERT INTO devices (network, ip, mac, level, score)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            network,
            d.get("ip"),
            d.get("mac"),
            d.get("level", "LOW"),
            risk
        ))

        # 🚨 REAL-TIME ALERT
        if risk >= 70:
            socketio.emit("security_alert", {
                "type": "HIGH_RISK_DEVICE",
                "ip": d.get("ip"),
                "score": risk
            })

    conn.commit()
    cur.close()
    conn.close()

    socketio.emit("device_update", {"network": network})

    return jsonify({"status": "stored"})


# =========================
# INTELLIGENCE API
# =========================
@app.route("/intelligence", methods=["GET"])
def intelligence():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT ip, mac, level, score
        FROM devices
        ORDER BY score DESC
        LIMIT 20
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    high_risk = [r for r in rows if r[3] >= 70]

    return jsonify({
        "high_risk_count": len(high_risk),
        "top_risks": [
            {
                "ip": r[0],
                "mac": r[1],
                "level": r[2],
                "score": r[3]
            }
            for r in high_risk
        ]
    })


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
        status = "online" if (now - last_seen) < timedelta(seconds=30) else "offline"

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
        SELECT ip, mac, level, score
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
            "score": r[3]
        }
        for r in rows
    ])


# =========================
# START
# =========================
if __name__ == "__main__":
    init_tables()

    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )