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
from database import init_db, log_scan, log_devices


# =========================
# CONFIG
# =========================

API_URL = "https://netwatch-api-02.onrender.com"

app = Flask(__name__)
app.secret_key = "netwatch_secret_key"

socketio = SocketIO(app)

ai_engine = AnomalyEngine()

# Initialize database
init_db()


# =========================
# LOGIN ROUTE
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # Simple temporary authentication
        if username == "admin" and password == "admin123":

            session["user"] = username

            return redirect(url_for("dashboard"))

    return render_template("login.html")


# =========================
# LOGOUT ROUTE
# =========================
@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect(url_for("login"))


# =========================
# DASHBOARD ROUTE
# =========================
@app.route("/")
def dashboard():

    # Require login
    if "user" not in session:
        return redirect(url_for("login"))

    # Fetch network data from API server
    try:

        response = requests.get(f"{API_URL}/devices")

        if response.status_code == 200:
            data = response.json()
        else:
            data = {}

    except Exception as e:

        print("API Error:", e)

        data = {}

    # Available networks
    networks = list(data.keys()) if data else []

    selected_network = request.args.get("network")

    # Default to first network
    if not selected_network and networks:
        selected_network = networks[0]

    # Safe device extraction
    if selected_network and selected_network in data:

        devices = data[selected_network]["devices"]

    else:

        devices = []

    # =========================
    # AI ANALYSIS
    # =========================

    ai_result = ai_engine.score(devices)

    known_devices = load_baseline()

    analyzed = []

    for d in devices:

        result = analyze_device(d, known_devices)

        analyzed.append(result)

    # =========================
    # DATABASE LOGGING
    # =========================

    log_scan(selected_network or "unknown", len(devices))

    log_devices(selected_network or "unknown", analyzed)

    # =========================
    # RENDER PAGE
    # =========================

    return render_template(
        "index.html",
        devices=analyzed,
        ai=ai_result,
        networks=networks,
        selected_network=selected_network
    )


# =========================
# REAL-TIME STREAMING
# =========================
def stream_data():

    while True:

        try:

            response = requests.get(f"{API_URL}/devices")

            if response.status_code == 200:

                data = response.json()

                socketio.emit("update", data)

        except Exception as e:

            print("Stream error:", e)

        socketio.sleep(5)


# =========================
# SOCKET CONNECT EVENT
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