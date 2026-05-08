import math
from network_scanner import load_baseline

class AnomalyEngine:
    def __init__(self):
        self.baseline_count = None

    def train(self, devices):
        # simple "learning": number of normal devices
        self.baseline_count = len(devices)

    def score(self, current_devices):
        if self.baseline_count is None:
            self.train(current_devices)

        current_count = len(current_devices)

        # anomaly based on deviation from baseline
        diff = abs(current_count - self.baseline_count)

        # normalize score (0–100)
        score = min(100, diff * 20)

        return {
            "baseline": self.baseline_count,
            "current": current_count,
            "anomaly_score": score,
            "is_anomaly": score > 50
        }