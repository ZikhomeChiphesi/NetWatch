import { useCallback, useEffect, useState } from "react";
import API from "../api/client";

function Topology() {
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState("");

  const loadDevices = useCallback(async () => {
    try {
      const response = await API.get("/devices");
      setDevices(response.data.devices || []);
      setError("");
    } catch (err) {
      setError(err.response?.data?.error || "Unable to load devices.");
    }
  }, []);

  useEffect(() => {
    const initialLoad = setTimeout(() => {
      void loadDevices();
    }, 0);

    const interval = setInterval(() => {
      void loadDevices();
    }, 15000);

    return () => {
      clearTimeout(initialLoad);
      clearInterval(interval);
    };
  }, [loadDevices]);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-4xl font-bold">Discovered Device Map</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Inventory view of devices discovered by NetWatch collectors. The current ARP telemetry does not establish physical or logical links between devices, so this page intentionally does not draw invented topology connections.
        </p>
      </div>

      {error && <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">{error}</div>}

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {devices.map((device) => (
          <div key={device.mac} className="rounded-xl border border-white/10 bg-white/5 p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-sm text-cyan-300">{device.mac}</p>
                <p className="mt-2 font-mono text-sm">{device.ip}</p>
              </div>
              <div className="flex flex-col items-end gap-2">
                <span className="rounded-full border border-white/10 bg-slate-900 px-2 py-1 text-xs">
                  {device.level}
                </span>

                <span className="rounded-full border border-white/10 bg-slate-900 px-2 py-1 text-xs">
                  {device.presence_status}
                </span>
              </div>
            </div>
            <dl className="mt-5 space-y-3 text-sm">
              <Row label="Vendor" value={device.vendor || "Unknown"} />
              <Row label="Network" value={device.network || "Unknown"} />
              <Row label="Risk score" value={device.score} />
              <Row label="First seen" value={formatDate(device.first_seen)} />
              <Row label="Last seen" value={formatDate(device.last_seen)} />
            </dl>
          </div>
        ))}
      </div>

      {devices.length === 0 && !error && (
        <div className="rounded-xl border border-white/10 bg-white/5 p-10 text-center text-slate-500">No devices have been observed yet.</div>
      )}
    </div>
  );
}

function Row({ label, value }) {
  return <div className="flex justify-between gap-4"><dt className="text-slate-500">{label}</dt><dd className="text-right text-slate-200">{value}</dd></div>;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

export default Topology;
