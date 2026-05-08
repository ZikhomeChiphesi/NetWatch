import os
import requests

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from flask_socketio import SocketIO

from network_scanner import load_baseline
from threat_engine import analyze_device
from anomaly_ai import AnomalyEngine

app = Flask(__name__)
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "netwatch_secret_key"
)

socketio = SocketIO(app)

API_URL = os.environ.get(
    "API_URL",
    "https://netwatch-api-02.onrender.com"
)

ai_engine = AnomalyEngine()


# =========================
# LOGIN
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":
            session["user"] = username
            return redirect(url_for("dashboard"))

    return render_template("login.html")


# =========================
# DASHBOARD
# =========================
@app.route("/")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    # -------------------------
    # FETCH DEVICES
    # -------------------------
    try:
        response = requests.get(f"{API_URL}/devices")

        devices = (
            response.json()
            if response.status_code == 200
            else []
        )

    except Exception as e:
        print("Device fetch failed:", e)
        devices = []

    # -------------------------
    # FETCH AGENTS
    # -------------------------
    try:
        agent_response = requests.get(f"{API_URL}/agents")

        agents = (
            agent_response.json()
            if agent_response.status_code == 200
            else []
        )

    except Exception as e:
        print("Agent fetch failed:", e)
        agents = []

    # -------------------------
    # AI ANALYSIS
    # -------------------------
    ai_result = ai_engine.score(devices)

    known_devices = load_baseline()

    analyzed = []

    for d in devices:
        analyzed.append(
            analyze_device(d, known_devices)
        )

    return render_template(
        "index.html",
        devices=analyzed,
        ai=ai_result,
        agents=agents
    )


# =========================
# REAL-TIME STREAMING
# =========================
def stream_data():

    while True:

        try:
            devices = requests.get(
                f"{API_URL}/devices"
            ).json()

            agents = requests.get(
                f"{API_URL}/agents"
            ).json()

            socketio.emit("update", {
                "devices": devices,
                "agents": agents
            })

        except Exception as e:
            print("Stream error:", e)

        socketio.sleep(5)


# =========================
# SOCKET CONNECT
# =========================
@socketio.on("connect")
def handle_connect():
    print("Client connected")


# =========================
# START APP
# =========================
if __name__ == "__main__":

    socketio.start_background_task(stream_data)

    port = int(os.environ.get("PORT", 10000))

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False
    )