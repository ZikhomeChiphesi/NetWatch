import { useCallback, useEffect, useState } from "react";
import API from "../api/client";

function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);

  const loadAlerts = useCallback(async () => {
    try {
      const response = await API.get("/alerts");
      setAlerts(response.data.alerts || []);
      setError("");
    } catch (err) {
      setError(err.response?.data?.error || "Unable to load alerts.");
    }
  }, []);

  useEffect(() => {
    const initialLoad = setTimeout(() => {
      void loadAlerts();
    }, 0);

    const interval = setInterval(() => {
      void loadAlerts();
    }, 15000);

    return () => {
      clearTimeout(initialLoad);
      clearInterval(interval);
    };
  }, [loadAlerts]);

  const transition = async (id, action) => {
    setBusyId(id);
    try {
      await API.post(`/alerts/${id}/${action}`);
      await loadAlerts();
    } catch (err) {
      setError(err.response?.data?.error || `Unable to ${action} alert.`);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-4xl font-bold">Alerts</h1>
        <p className="mt-2 text-slate-400">Persistent operator workflow with acknowledgement and resolution.</p>
      </div>

      {error && <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">{error}</div>}

      <div className="space-y-4">
        {alerts.map((alert) => (
          <article key={alert.id} className="rounded-xl border border-white/10 bg-white/5 p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-slate-900 px-2 py-1 text-xs">{alert.severity}</span>
                  <span className="rounded-full bg-slate-900 px-2 py-1 text-xs">{alert.status}</span>
                  <span className="text-xs text-slate-500">#{alert.id}</span>
                </div>
                <h2 className="mt-3 text-lg font-semibold">{alert.title}</h2>
                <p className="mt-2 max-w-3xl text-sm text-slate-400">{alert.description || "No additional description."}</p>
                <p className="mt-3 text-xs text-slate-500">
                  Device {alert.device_mac || "n/a"} · score {alert.score} · occurrences {alert.occurrences} · last seen {formatDate(alert.last_seen)}
                </p>
              </div>

              <div className="flex gap-2">
                {alert.status === "OPEN" && (
                  <button
                    disabled={busyId === alert.id}
                    onClick={() => transition(alert.id, "acknowledge")}
                    className="rounded-lg border border-cyan-500/30 px-3 py-2 text-sm text-cyan-300 disabled:opacity-50"
                  >
                    Acknowledge
                  </button>
                )}
                {alert.status !== "RESOLVED" && (
                  <button
                    disabled={busyId === alert.id}
                    onClick={() => transition(alert.id, "resolve")}
                    className="rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
                  >
                    Resolve
                  </button>
                )}
              </div>
            </div>
          </article>
        ))}
      </div>

      {alerts.length === 0 && !error && (
        <div className="rounded-xl border border-white/10 bg-white/5 p-10 text-center text-slate-500">No alerts have been recorded.</div>
      )}
    </div>
  );
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

export default Alerts;
