def analyze_device(device, known_devices):
    known_macs = {d["mac"] for d in known_devices}

    score = 0
    reasons = []
    is_new = False

    # Check if device is new
    if device["mac"] not in known_macs:
        score += 80
        reasons.append("Unknown device detected")
        is_new = True

    # Basic IP anomaly check
    if not device["ip"].startswith("192.168.1."):
        score += 15
        reasons.append("Unusual IP range")

    # Risk classification
    if score >= 70:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "ip": device["ip"],
        "mac": device["mac"],
        "score": score,
        "level": level,
        "reasons": reasons,
        "is_new": is_new
    }