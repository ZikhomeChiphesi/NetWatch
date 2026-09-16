import os
import time
import requests

from network_scanner import scan_network

# =========================
# CONFIG
# =========================

API_URL = "http://127.0.0.1:5000"

ORG_ID = "UNZA-LOCAL"

NETWORK_NAME = "Home_Network"

KEY_FILE = "agent_key.txt"

SCAN_RANGE = "172.16.23.0/24"

# =========================
# REGISTER / LOAD API KEY
# =========================

def get_or_register():

    # Load existing key
    if os.path.exists(KEY_FILE):

        with open(KEY_FILE, "r") as f:
            key = f.read().strip()

        if key:
            print("[INFO] Loaded existing API key")
            return key

    # Register new agent
    print("[INFO] Registering agent...")

    try:

        res = requests.post(
            f"{API_URL}/register",
            json={
                "org_id": ORG_ID,
                "network": NETWORK_NAME
            },
            timeout=10
        )

        res.raise_for_status()

        data = res.json()

        key = data["api_key"]

        with open(KEY_FILE, "w") as f:
            f.write(key)

        print("[SUCCESS] Agent registered")
        print("[AGENT ID]", data["agent_id"])
        print("[ORG ID]", data["org_id"])

        return key

    except Exception as e:

        print("[ERROR] Registration failed:", e)

        return None


# =========================
# AUTH HEADERS
# =========================

def auth_headers(api_key):

    return {
        "X-API-Key": api_key,
        "X-ORG-ID": ORG_ID
    }


# =========================
# HEARTBEAT
# =========================

def send_heartbeat(api_key):

    try:

        res = requests.post(
            f"{API_URL}/heartbeat",
            headers=auth_headers(api_key),
            timeout=5
        )

        print("[HEARTBEAT]", res.status_code)

    except Exception as e:

        print("[ERROR] Heartbeat failed:", e)


# =========================
# MAIN LOOP
# =========================

def run_agent():

    api_key = get_or_register()

    if not api_key:

        print("[FATAL] No API key available")
        return

    print("[INFO] Agent started")
    print("[INFO] Organization:", ORG_ID)
    print("[INFO] Network:", SCAN_RANGE)

    while True:

        try:

            print("\n[SCAN] Scanning network...")

            start = time.time()

            devices = scan_network(SCAN_RANGE)

            duration = round(time.time() - start, 2)

            print(f"[SCAN COMPLETE] {len(devices)} devices found")
            print(f"[TIME] {duration}s")

            payload = {
                "network": NETWORK_NAME,
                "devices": devices,
                "timestamp": time.time()
            }

            print("[UPLOAD] Sending data to backend...")

            res = requests.post(
                f"{API_URL}/upload",
                json=payload,
                headers=auth_headers(api_key),
                timeout=10
            )

            print("[UPLOAD]", res.status_code)

            if res.status_code != 200:
                print("[UPLOAD RESPONSE]", res.text)

            send_heartbeat(api_key)

        except Exception as e:

            print("[ERROR]", e)

        print("[SLEEP] Waiting 10 seconds...\n")

        time.sleep(10)


# =========================
# START
# =========================

if __name__ == "__main__":
    run_agent()