import os
import functools
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv

from database import init_db, log_scan, log_devices

# OPTIONAL: if you still use auth later
# from auth import auth_bp, login_manager, init_users_table

load_dotenv()

# ─────────────────────────────────────
# Flask + SocketIO setup
# ─────────────────────────────────────
app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret")

# IMPORTANT: Render needs async mode compatible with eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ─────────────────────────────────────
# In-memory cache (temporary state layer)
# ─────────────────────────────────────
network_data = {}

# ─────────────────────────────────────
# Environment variables
# ─────────────────────────────────────
API_KEY = os.getenv("API_KEY")

# ─────────────────────────────────────
# API KEY SECURITY
# ─────────────────────────────────────
def require_api_key(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")

        if not API_KEY or key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)

    return wrapper


# ─────────────────────────────────────
# AGENT ENDPOINT (UPLOAD DATA)
# ─────────────────────────────────────
@app.route("/upload", methods=["POST"])
@require_api_key
def upload_data():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No JSON body"}), 400

    network = data.get("network", "unknown")
    devices = data.get("devices", [])

    # store latest snapshot
    network_data[network] = data

    # persist to PostgreSQL (Render DB)
    try:
        log_scan(network, len(devices))
        log_devices(network, devices)
    except Exception as e:
        print("DB error:", e)

    # push real-time update to dashboard
    socketio.emit("update", network_data)

    return jsonify({
        "status": "received",
        "devices_count": len(devices)
    })


# ─────────────────────────────────────
# DASHBOARD API
# ─────────────────────────────────────
@app.route("/devices", methods=["GET"])
def get_devices():
    return jsonify(network_data)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "NetWatch API"
    })


# ─────────────────────────────────────
# INIT DB ON STARTUP
# ─────────────────────────────────────
init_db()


# ─────────────────────────────────────
# RENDER ENTRYPOINT
# ─────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))

    print(f"Starting NetWatch API on port {port}")

    socketio.run(
        app,
        host="0.0.0.0",
        port=port
    )