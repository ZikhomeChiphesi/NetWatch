from flask import Flask, render_template
from network_scanner import scan_network, load_baseline
from threat_engine import analyze_device

app = Flask(__name__)

TARGET_NETWORK = "192.168.1.1/24"


@app.route("/")
def dashboard():
    devices = scan_network(TARGET_NETWORK)
    known_devices = load_baseline()

    analyzed = []

    for d in devices:
        result = analyze_device(d, known_devices)
        analyzed.append(result)

    return render_template("index.html", devices=analyzed)


if __name__ == "__main__":
    app.run(debug=True)