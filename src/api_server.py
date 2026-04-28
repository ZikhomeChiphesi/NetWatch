from flask import Flask, request, jsonify

app = Flask(__name__)

# temporary in-memory storage (we upgrade later to DB)
network_data = {}


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
    app.run(port=5001, debug=True)