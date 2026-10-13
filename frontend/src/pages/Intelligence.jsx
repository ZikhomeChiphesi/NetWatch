import { useEffect, useState } from "react";
import API from "../api/client";

function Intelligence() {
  const [intel, setIntel] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    API.get("/intelligence")
      .then((response) => setIntel(response.data))
      .catch((err) => setError(err.response?.data?.error || "Unable to load risk data."));
  }, []);

  if (error) {
    return <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-5 text-red-300">{error}</div>;
  }

  if (!intel) {
    return <p className="text-slate-400">Loading measured risk signals...</p>;
  }

  return (
    <div>
      <h1 className="text-4xl font-bold">Risk Intelligence</h1>
      <p className="mt-2 max-w-3xl text-slate-400">
        This page shows deterministic, explainable risk signals from current NetWatch telemetry. It does not claim machine-learning anomaly detection.
      </p>

      <div className="mt-8 grid grid-cols-1 gap-5 md:grid-cols-3">
        <Card label="Average current risk" value={Number(intel.avg_risk || 0).toFixed(1)} />
        <Card label="Current high-risk devices" value={intel.high_risk_devices || 0} />
        <Card
          label="Unresolved alerts"
          value={intel.unresolved_alerts || 0}
        />
      </div>

      <div className="mt-8 overflow-hidden rounded-xl border border-white/10 bg-white/5">
        <div className="border-b border-white/10 p-5">
          <h2 className="text-xl font-semibold">Highest current risk devices</h2>
        </div>
        <table className="w-full text-left">
          <thead className="text-xs uppercase text-slate-500">
            <tr><th className="p-4">MAC</th><th className="p-4">IP</th><th className="p-4">Level</th><th className="p-4">Score</th><th className="p-4">Last seen</th></tr>
          </thead>
          <tbody>
            {(intel.risky_devices || []).map((device) => (
              <tr key={device.mac} className="border-t border-white/5">
                <td className="p-4 font-mono text-sm">{device.mac}</td>
                <td className="p-4 font-mono text-sm">{device.ip}</td>
                <td className="p-4">{device.level}</td>
                <td className="p-4 font-bold">{device.score}</td>
                <td className="p-4 text-sm text-slate-400">{device.last_seen ? new Date(device.last_seen).toLocaleString() : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Card({ label, value }) {
  return <div className="rounded-xl border border-white/10 bg-white/5 p-6"><p className="text-sm text-slate-500">{label}</p><p className="mt-2 text-4xl font-bold text-cyan-300">{value}</p></div>;
}

export default Intelligence;
