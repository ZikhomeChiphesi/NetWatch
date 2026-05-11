import json
import os

BASELINE_FILE = "trusted_devices.json"


# =========================
# LOAD TRUSTED DEVICES
# =========================
def load_trusted_devices():

    if not os.path.exists(BASELINE_FILE):
        return []

    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


# =========================
# SAVE TRUSTED DEVICES
# =========================
def save_trusted_devices(devices):

    with open(BASELINE_FILE, "w") as f:
        json.dump(devices, f, indent=4)


# =========================
# AUTO-TRUST BASELINE
# =========================
def initialize_baseline(devices):

    trusted = load_trusted_devices()

    if trusted:
        return

    macs = [d["mac"] for d in devices]

    save_trusted_devices(macs)

    print("[BASELINE] Trusted devices initialized")


# =========================
# CHECK TRUST STATUS
# =========================
def is_trusted(mac):

    trusted = load_trusted_devices()

    return mac in trusted


# =========================
# ADD TRUSTED DEVICE
# =========================
def add_trusted_device(mac):

    trusted = load_trusted_devices()

    if mac not in trusted:
        trusted.append(mac)

    save_trusted_devices(trusted)


# =========================
# DEVICE ANALYSIS
# =========================
def analyze_device(device):

    mac = device.get("mac", "unknown")
    ip = device.get("ip", "unknown")

    score = 0
    reasons = []

    trusted = is_trusted(mac)

    # =========================
    # UNKNOWN DEVICE
    # =========================
    if not trusted:

        score += 70

        reasons.append(
            "Unknown / untrusted device detected"
        )

    # =========================
    # UNUSUAL IP RANGE
    # =========================
    if not ip.startswith("192.168."):

        score += 15

        reasons.append(
            "Unusual IP range"
        )

    # =========================
    # THREAT LEVEL
    # =========================
    if score >= 80:
        severity = "CRITICAL"

    elif score >= 60:
        severity = "HIGH"

    elif score >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # =========================
    # CONFIDENCE SCORE
    # =========================
    confidence = min(100, score + 20)

    # =========================
    # SUSPICIOUS FLAG
    # =========================
    suspicious = (
        not trusted and score >= 60
    )

    # =========================
    # VENDOR PLACEHOLDER
    # =========================
    vendor = "Unknown Vendor"

    return {
        "ip": ip,
        "mac": mac,
        "score": score,
        "severity": severity,
        "confidence": confidence,
        "trusted": trusted,
        "suspicious": suspicious,
        "vendor": vendor,
        "reasons": reasons
    }