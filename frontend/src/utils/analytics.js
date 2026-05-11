export function computeRiskTrend(devices) {
  if (!devices || devices.length === 0) return [];

  const grouped = devices.slice(-10).map((d, i) => ({
    time: `${i + 1}m`,
    risk: d.score || 0
  }));

  return grouped;
}

export function computeThreatDistribution(devices) {
  let low = 0, med = 0, high = 0;

  devices.forEach(d => {
    if (d.score < 30) low++;
    else if (d.score < 70) med++;
    else high++;
  });

  return [
    { name: "LOW", value: low },
    { name: "MED", value: med },
    { name: "HIGH", value: high }
  ];
}

export function computeSeverityRatio(anomalies = []) {
  const threat = anomalies.length;
  const normal = Math.max(0, 100 - threat * 10);

  return [
    { name: "Normal", value: normal },
    { name: "Threat", value: threat * 10 }
  ];
}