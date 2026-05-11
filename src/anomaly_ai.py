import random


class AnomalyEngine:

    def __init__(self):

        self.baseline_count = None

    # =========================
    # BASELINE TRAINING
    # =========================
    def train(self, devices):

        self.baseline_count = len(devices)

    # =========================
    # BASIC SYSTEM SCORE
    # =========================
    def score(self, current_devices):

        if self.baseline_count is None:
            self.train(current_devices)

        current_count = len(current_devices)

        diff = abs(
            current_count - self.baseline_count
        )

        score = min(100, diff * 20)

        return {
            "baseline": self.baseline_count,
            "current": current_count,
            "anomaly_score": score,
            "is_anomaly": score > 50
        }

    # =========================
    # ADVANCED DEVICE ANALYSIS
    # =========================
    def analyze(self, devices):

        anomalies = []

        total_risk = 0

        analyzed = []

        for d in devices:

            score = d.get("score", 0)

            level = d.get("level", "LOW")

            anomaly_score = self.calculate_anomaly(
                score,
                level
            )

            confidence = self.confidence_score(
                anomaly_score
            )

            classification = self.classify(
                anomaly_score
            )

            enriched = {
                **d,
                "anomaly_score": anomaly_score,
                "confidence": confidence,
                "classification": classification
            }

            analyzed.append(enriched)

            total_risk += anomaly_score

            # DETECT HIGH-RISK EVENTS
            if anomaly_score > 70:

                anomalies.append(
                    f"Critical anomaly detected on {d.get('ip')}"
                )

        avg_risk = (
            total_risk / len(devices)
            if devices
            else 0
        )

        return {
            "device_count": len(devices),
            "avg_risk": avg_risk,
            "anomalies": anomalies,
            "devices": analyzed
        }

    # =========================
    # CALCULATE ANOMALY SCORE
    # =========================
    def calculate_anomaly(self, score, level):

        base = score

        if level == "HIGH":

            base += 40

        elif level == "MED":

            base += 20

        else:

            base += 5

        # RANDOMIZED VARIATION
        noise = random.randint(0, 15)

        return min(base + noise, 100)

    # =========================
    # CONFIDENCE SCORE
    # =========================
    def confidence_score(self, anomaly_score):

        return round(
            anomaly_score / 100,
            2
        )

    # =========================
    # THREAT CLASSIFICATION
    # =========================
    def classify(self, anomaly_score):

        if anomaly_score >= 80:
            return "CRITICAL"

        if anomaly_score >= 60:
            return "SUSPICIOUS"

        if anomaly_score >= 30:
            return "WARNING"

        return "NORMAL"