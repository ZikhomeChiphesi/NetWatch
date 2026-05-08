import os
from flask import Flask, request, jsonify

app = Flask(__name__)

network_data = {}

@app.route("/")
def home():
    return jsonify({
        "status": "NetWatch API running"
    })

@app.route("/upload", methods=["POST"])
def upload_data():
    data = request.json
    network = data.get("network", "unknown")

    network_data[network] = data

    return jsonify({"status": "received"})


@app.route("/devices", methods=["GET"])
def get_devices():
    return jsonify(network_data)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)