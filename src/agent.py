import time
import requests
from network_scanner import scan_network

API_URL = "https://netwatch-api-02.onrender.com/upload"
TARGET = "192.168.1.1/24"
NETWORK_NAME = "Home_Network"   # change per location later

def run_agent():
    while True:
        devices = scan_network(TARGET)

        payload = {
            "network": NETWORK_NAME,
            "devices": devices,
            "timestamp": time.time()
        }

        try:
            requests.post(API_URL, json=payload)
            print("Sent data to server")

        except Exception as e:
            print("Failed:", e)

        time.sleep(10)


if __name__ == "__main__":
    run_agent()