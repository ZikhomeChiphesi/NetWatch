import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO

from network_scanner import load_baseline
from threat_engine import analyze_device
from anomaly_ai import AnomalyEngine

from database import init_db, log_scan, log_devices

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

socketio = SocketIO(app, cors_allowed_origins="*")

API_URL = os.getenv("API_URL", "http://127.0.0.1:5001")

ai_engine = AnomalyEngine()

init_db()


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "admin123":
            session["user"] = "admin"
            return redirect(url_for("dashboard"))
    return render_template("login.html")


# =========================
# DASHBOARD
# =========================

@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    selected_network = request.args.get("network", "default")

    try:
        response = requests.get(f"{API_URL}/devices?network={selected_network}")
        devices = response.json()
    except:
        devices = []

    ai_result = ai_engine.score(devices)
    known_devices = load_baseline()

    analyzed = [analyze_device(d, known_devices) for d in devices]

    log_scan(selected_network, len(devices))
    log_devices(selected_network, analyzed)

    return render_template(
        "index.html",
        devices=analyzed,
        ai=ai_result,
        networks=[selected_network],
        selected_network=selected_network
    )


# =========================
# SOCKET STREAM
# =========================

def stream_data():
    while True:
        try:
            data = requests.get(f"{API_URL}/devices").json()
            socketio.emit("update", data)
        except:
            pass

        socketio.sleep(5)


@socketio.on("connect")
def on_connect():
    print("Client connected")


# =========================
# START
# =========================

if __name__ == "__main__":
    socketio.start_background_task(stream_data)

    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
        debug=False
    )