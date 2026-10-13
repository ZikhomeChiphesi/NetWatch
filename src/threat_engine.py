from __future__ import annotations

import ipaddress
import re
from typing import Any

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def normalize_mac(mac: str | None) -> str:
    if not mac:
        return "unknown"
    return mac.strip().lower().replace("-", ":")


def _severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def analyze_device(
    device: dict[str, Any],
    *,
    trusted: bool = False,
    expected_network_cidr: str | None = None,
) -> dict[str, Any]:
    """
    Explainable deterministic risk scoring for the telemetry NetWatch actually has today.

    Important design rule: private address families are not considered suspicious by
    themselves. Network membership is evaluated against the collector's configured
    CIDR, not against a hard-coded 192.168/16 assumption.
    """

    raw_ip = str(device.get("ip") or "").strip()
    mac = normalize_mac(device.get("mac"))
    score = 0
    reasons: list[dict[str, Any]] = []

    try:
        ip_obj = ipaddress.ip_address(raw_ip)
        valid_ip = True
    except ValueError:
        ip_obj = None
        valid_ip = False
        score += 35
        reasons.append(
            {
                "signal": "invalid_ip",
                "weight": 35,
                "detail": "The reported IP address is not syntactically valid.",
            }
        )

    if not MAC_RE.match(mac):
        score += 35
        reasons.append(
            {
                "signal": "invalid_mac",
                "weight": 35,
                "detail": "The reported MAC address is missing or malformed.",
            }
        )

    if not trusted:
        score += 40
        reasons.append(
            {
                "signal": "untrusted_device",
                "weight": 40,
                "detail": "The device is not marked as trusted for this organization.",
            }
        )

    if valid_ip and expected_network_cidr:
        try:
            expected_network = ipaddress.ip_network(expected_network_cidr, strict=False)
            if ip_obj not in expected_network:
                score += 25
                reasons.append(
                    {
                        "signal": "outside_expected_network",
                        "weight": 25,
                        "detail": (
                            f"The address {raw_ip} is outside the collector's configured "
                            f"network {expected_network_cidr}."
                        ),
                    }
                )
        except ValueError:
            # A bad server-side collector configuration should not make every endpoint
            # look malicious. Configuration health is reported separately by the API.
            reasons.append(
                {
                    "signal": "collector_network_unconfigured",
                    "weight": 0,
                    "detail": "The collector's configured CIDR could not be evaluated.",
                }
            )

    score = max(0, min(100, score))
    level = _severity(score)

    evidence_count = len([reason for reason in reasons if reason["weight"] > 0])
    confidence = min(95, 45 + evidence_count * 15) if evidence_count else 40

    return {
        "ip": raw_ip or "unknown",
        "mac": mac,
        "score": score,
        "level": level,
        "confidence": confidence,
        "trusted": trusted,
        "suspicious": score >= 60,
        "reasons": reasons,
    }
