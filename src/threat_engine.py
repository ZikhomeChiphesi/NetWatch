def analyze_device(device, known_devices):
    """
    Returns a risk score and label for a device.
    """

    known_macs = {d["mac"] for d in known_devices}

    score = 0
    reasons = []

    # Rule 1: Unknown device
    if device["mac"] not in known_macs:
        score += 70
        reasons.append("Unknown device")

    # Rule 2: Suspicious IP range (example heuristic)
    if device["ip"].startswith("192.168.1.") is False:
        score += 20
        reasons.append("Unusual IP range")

    # Rule 3: Default/empty MAC pattern check (basic placeholder logic)
    if device["mac"].count("00") > 4:
        score += 10
        reasons.append("Weak MAC pattern")

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
        "reasons": reasons
    }