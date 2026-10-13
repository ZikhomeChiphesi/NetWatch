import { useCallback, useEffect, useMemo, useState } from "react";
import { io } from "socket.io-client";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import API, { API_BASE_URL } from "../api/client";

const STATUS_LABELS = {
  NO_AGENTS: "NO COLLECTORS",
  COLLECTORS_STALE: "COLLECTORS STALE",
  ATTENTION: "ATTENTION REQUIRED",
  MONITORING: "MONITORING",
};

function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadSummary = useCallback(async () => {
    try {
      const response = await API.get("/dashboard/summary");
      setSummary(response.data);
      setError("");
    } catch (err) {
      setError(err.response?.data?.error || "Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = setTimeout(() => {
      void loadSummary();
    }, 0);

    const interval = setInterval(() => {
      void loadSummary();
    }, 15000);

    const token = localStorage.getItem("session_token");
    const orgId = localStorage.getItem("org_id");

    const socket = io(API_BASE_URL, {
      auth: { token, org_id: orgId },
      transports: ["websocket", "polling"],
    });

    socket.on("device_update", loadSummary);
    socket.on("agent_update", loadSummary);
    socket.on("alert_update", loadSummary);

    return () => {
      clearTimeout(initialLoad);
      clearInterval(interval);

      socket.off("device_update", loadSummary);
      socket.off("agent_update", loadSummary);
      socket.off("alert_update", loadSummary);

      socket.disconnect();
    };
  }, [loadSummary]);

  const trendData = useMemo(
    () =>
      (summary?.risk_trend || []).map((item) => ({
        ...item,
        label: item.time ? new Date(item.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "",
      })),
    [summary]
  );

  const status = summary?.system_status || "NO_AGENTS";

  if (loading) {
    return <p className="text-slate-400">Loading measured network data...</p>;
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-4xl font-bold">Security Operations Dashboard</h1>
        <p className="mt-2 text-slate-400">
          Current inventory, measured risk signals, collector health, and alert state.
        </p>
      </div>

      {error && (
        <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">
          {error}
        </div>
      )}

      <div className="mb-8 grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Online devices" value={summary?.online_devices || 0} />
        <MetricCard label="Known assets" value={summary?.known_devices || 0} />
        <MetricCard label="Average current risk" value={Number(summary?.avg_risk || 0).toFixed(1)} />
        <MetricCard label="Current high-risk" value={summary?.high_risk_devices || 0} />
        <MetricCard label="Unresolved alerts" value={summary?.unresolved_alerts || 0} />
        <MetricCard label="System state" value={STATUS_LABELS[status] || status} compact />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="h-[340px] rounded-2xl border border-white/10 bg-white/5 p-6">
          <h2 className="text-xl font-semibold">Measured risk trend - last 60 minutes</h2>
          <p className="mt-1 text-sm text-slate-500">Average stored observation risk by minute.</p>
          {trendData.length === 0 ? (
            <EmptyChart message="No observations have been stored in the last hour." />
          ) : (
            <ResponsiveContainer width="100%" height="82%">
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
                <XAxis dataKey="label" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Line type="monotone" dataKey="risk" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </section>

        <section className="h-[340px] rounded-2xl border border-white/10 bg-white/5 p-6">
          <h2 className="text-xl font-semibold">Current risk distribution</h2>
          <p className="mt-1 text-sm text-slate-500">Classification of current device records.</p>
          <ResponsiveContainer width="100%" height="82%">
            <BarChart data={summary?.risk_distribution || []}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="value" />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="rounded-2xl border border-white/10 bg-white/5 p-6">
          <h2 className="text-xl font-semibold">Collector health</h2>
          <div className="mt-5 grid grid-cols-3 gap-4">
            <SmallMetric label="Total" value={summary?.total_agents || 0} />
            <SmallMetric label="Active" value={summary?.active_agents || 0} />
            <SmallMetric label="Stale" value={summary?.stale_agents || 0} />
          </div>
          <p className="mt-5 text-sm text-slate-500">
            Last device observation: {formatDate(summary?.last_device_seen)}
          </p>
        </section>

        <section className="rounded-2xl border border-white/10 bg-white/5 p-6">
          <h2 className="text-xl font-semibold">Highest current risk</h2>
          <div className="mt-4 space-y-3">
            {(summary?.risky_devices || []).length === 0 ? (
              <p className="text-sm text-slate-500">No device records yet.</p>
            ) : (
              summary.risky_devices.slice(0, 5).map((device) => (
                <div key={device.mac} className="flex items-center justify-between rounded-xl bg-slate-950/60 p-4">
                  <div>
                    <p className="font-mono text-sm text-white">{device.mac}</p>
                    <p className="mt-1 text-xs text-slate-500">{device.ip} · {device.level}</p>
                  </div>
                  <span className="text-xl font-bold">{device.score}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function MetricCard({ label, value, compact = false }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-5">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`${compact ? "text-xl" : "text-3xl"} mt-3 font-bold text-cyan-300`}>{value}</p>
    </div>
  );
}

function SmallMetric({ label, value }) {
  return (
    <div className="rounded-xl bg-slate-950/60 p-4">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
    </div>
  );
}

function EmptyChart({ message }) {
  return <div className="flex h-[80%] items-center justify-center text-sm text-slate-500">{message}</div>;
}

function formatDate(value) {
  if (!value) return "No data yet";
  return new Date(value).toLocaleString();
}

export default Dashboard;
