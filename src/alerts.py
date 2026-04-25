import time
from datetime import datetime

ALERT_LOG = "logs/alerts.log"

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"

    print("ALERT:", message)

    with open(ALERT_LOG, "a") as f:
        f.write(entry)


def detect_new_devices(current_devices, known_devices):
    known_macs = {d["mac"] for d in known_devices}

    new_devices = []

    for device in current_devices:
        if device["mac"] not in known_macs:
            new_devices.append(device)
            log_alert(f"New device detected: {device['ip']} ({device['mac']})")

    return new_devices


def trigger_threat_alert(device, reason="HIGH RISK DEVICE"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = (
        f"[THREAT ALERT] {timestamp} | "
        f"{reason} | "
        f"{device['ip']} ({device['mac']})"
    )

    print("\n🚨 ALERT:", message)

    with open(ALERT_LOG, "a") as f:
        f.write(message + "\n")