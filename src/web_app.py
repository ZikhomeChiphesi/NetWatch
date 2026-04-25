from flask import Flask, render_template, request, redirect, url_for, session
from network_scanner import scan_network, load_baseline
from threat_engine import analyze_device

app = Flask(__name__)
app.secret_key = "netwatch_secret_key"

TARGET_NETWORK = "192.168.1.1/24"


# ✅ LOGIN ROUTE (MUST EXIST FIRST)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":
            session["user"] = username
            return redirect(url_for("dashboard"))

    return render_template("login.html")


# ✅ DASHBOARD ROUTE
@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    devices = scan_network(TARGET_NETWORK)
    known_devices = load_baseline()

    analyzed = []

    for d in devices:
        result = analyze_device(d, known_devices)
        analyzed.append(result)

    return render_template("index.html", devices=analyzed)


if __name__ == "__main__":
    app.run(debug=True)