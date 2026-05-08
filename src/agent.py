import os
import time
import requests
from network_scanner import scan_network

API_URL = "https://netwatch-api-02.onrender.com"
NETWORK_NAME = "Home_Network"

KEY_FILE = "agent_key.txt"


# =========================
# REGISTER OR LOAD
# =========================
def get_or_register():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            return f.read().strip()

    res = requests.post(f"{API_URL}/register", json={
        "network": NETWORK_NAME
    })

    data = res.json()

    key = data["api_key"]

    with open(KEY_FILE, "w") as f:
        f.write(key)

    print("Registered agent:", data["agent_id"])
    return key


# =========================
# HEARTBEAT
# =========================
def send_heartbeat(api_key):
    try:
        requests.post(
            f"{API_URL}/heartbeat",
            headers={"X-API-Key": api_key}
        )
    except:
        pass


# =========================
# MAIN LOOP
# =========================
def run_agent():
    api_key = get_or_register()

    while True:
        devices = scan_network("192.168.1.1/24")

        payload = {
            "network": NETWORK_NAME,
            "devices": devices,
            "timestamp": time.time()
        }

        try:
            requests.post(
                f"{API_URL}/upload",
                json=payload,
                headers={"X-API-Key": api_key}
            )
        except Exception as e:
            print("Upload failed:", e)

        # 🫀 HEARTBEAT EVERY LOOP
        send_heartbeat(api_key)

        time.sleep(10)


if __name__ == "__main__":
    run_agent()