import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://localhost:5000";

function Topology() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDevices = async () => {
    try {
      setLoading(true);
      setError("");

      const orgId = localStorage.getItem("org_id");

      if (!orgId) {
        throw new Error("Organization ID is missing. Please log in again.");
      }

      const response = await axios.get(`${API_URL}/devices`, {
        headers: {
          "X-ORG-ID": orgId,
        },
      });

      const data = response.data;

      // Backend returns { devices: [...] }
      setDevices(Array.isArray(data) ? data : data.devices || []);

    } catch (err) {
      console.error("Topology error:", err);

      setError(
        err.response?.data?.error ||
          err.message ||
          "Unable to load network devices."
      );

      setDevices([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDevices();

    const interval = setInterval(loadDevices, 10000);

    return () => clearInterval(interval);
  }, []);

  const getRiskClass = (score) => {
    if (score >= 70) {
      return "text-red-400 bg-red-500/10 border-red-500/20";
    }

    if (score >= 40) {
      return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
    }

    return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  };

  const getRiskLabel = (score) => {
    if (score >= 70) return "HIGH RISK";
    if (score >= 40) return "MEDIUM";
    return "LOW RISK";
  };

  return (
    <div className="min-h-full">

      {/* HEADER */}
      <div className="mb-8">

        <div className="flex items-center justify-between">

          <div>
            <h1 className="text-4xl font-bold text-white">
              Network Topology
            </h1>

            <p className="text-slate-400 mt-2">
              Real-time infrastructure visualization
            </p>
          </div>

          <button
            onClick={loadDevices}
            className="px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 transition"
          >
            Refresh
          </button>

        </div>

      </div>

      {/* SUMMARY */}
      <div className="grid grid-cols-4 gap-5 mb-8">

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">
            Devices
          </p>

          <p className="text-3xl font-bold text-cyan-400 mt-2">
            {devices.length}
          </p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">
            High Risk
          </p>

          <p className="text-3xl font-bold text-red-400 mt-2">
            {devices.filter((d) => Number(d.score) >= 70).length}
          </p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">
            Medium Risk
          </p>

          <p className="text-3xl font-bold text-yellow-400 mt-2">
            {
              devices.filter(
                (d) =>
                  Number(d.score) >= 40 &&
                  Number(d.score) < 70
              ).length
            }
          </p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">
            Network Status
          </p>

          <p className="text-xl font-bold text-emerald-400 mt-3">
            {devices.length > 0 ? "MONITORED" : "WAITING"}
          </p>
        </div>

      </div>

      {/* ERROR */}
      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300">

          <p className="font-semibold">
            Network data unavailable
          </p>

          <p className="text-sm mt-1">
            {error}
          </p>

        </div>
      )}

      {/* TOPOLOGY */}
      <div className="bg-slate-900/60 border border-white/10 rounded-2xl overflow-hidden">

        <div className="p-5 border-b border-white/10 flex items-center justify-between">

          <div>
            <h2 className="text-xl font-semibold text-white">
              Live Network Map
            </h2>

            <p className="text-sm text-slate-500 mt-1">
              Devices discovered by NetWatch
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            LIVE
          </div>

        </div>

        {loading ? (

          <div className="p-16 text-center">
            <p className="text-slate-400">
              Discovering network devices...
            </p>
          </div>

        ) : devices.length === 0 ? (

          <div className="p-16 text-center">

            <div className="text-5xl mb-4">
              ◎
            </div>

            <h3 className="text-xl text-white">
              No network devices found
            </h3>

            <p className="text-slate-400 mt-2">
              NetWatch is waiting for network telemetry.
            </p>

          </div>

        ) : (

          <div className="p-8">

            {/* ROUTER */}
            <div className="flex justify-center">

              <div className="w-56 rounded-2xl border border-cyan-500/30 bg-cyan-500/10 p-5 text-center shadow-lg shadow-cyan-500/5">

                <div className="text-3xl mb-2">
                  ◈
                </div>

                <p className="text-cyan-300 font-bold">
                  NETWATCH
                </p>

                <p className="text-slate-400 text-xs mt-1">
                  Network Gateway
                </p>

                <div className="mt-3 inline-flex items-center gap-2 text-xs text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                  MONITORING
                </div>

              </div>

            </div>

            {/* CONNECTION LINE */}
            <div className="mx-auto w-px h-10 bg-cyan-500/40"></div>

            <div className="mx-auto max-w-5xl h-px bg-cyan-500/30"></div>

            {/* DEVICES */}
            <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5 mt-0">

              {devices.map((device, index) => {

                const score = Number(device.score || 0);

                return (

                  <div
                    key={`${device.mac}-${index}`}
                    className="relative pt-8"
                  >

                    {/* CONNECTION */}
                    <div className="absolute top-0 left-1/2 -translate-x-1/2 h-8 w-px bg-cyan-500/30"></div>

                    <div className="bg-slate-950 border border-white/10 rounded-xl p-5 hover:border-cyan-500/30 transition">

                      <div className="flex items-start justify-between gap-3">

                        <div>

                          <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-300 mb-3">
                            ◉
                          </div>

                          <p className="text-white font-semibold">
                            Device {index + 1}
                          </p>

                        </div>

                        <div
                          className={`px-2 py-1 rounded-md border text-xs ${getRiskClass(
                            score
                          )}`}
                        >
                          {getRiskLabel(score)}
                        </div>

                      </div>

                      <div className="mt-4 space-y-2">

                        <div>
                          <p className="text-xs text-slate-500">
                            IP ADDRESS
                          </p>

                          <p className="font-mono text-sm text-cyan-300">
                            {device.ip || "Unknown"}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            MAC ADDRESS
                          </p>

                          <p className="font-mono text-xs text-slate-400">
                            {device.mac || "Unknown"}
                          </p>
                        </div>

                        <div>
                          <p className="text-xs text-slate-500">
                            VENDOR
                          </p>

                          <p className="text-sm text-slate-300">
                            {device.vendor || "Unknown"}
                          </p>
                        </div>

                      </div>

                      <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">

                        <span className="text-xs text-slate-500">
                          Risk Score
                        </span>

                        <span
                          className={`font-bold ${
                            score >= 70
                              ? "text-red-400"
                              : score >= 40
                              ? "text-yellow-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {score}
                        </span>

                      </div>

                    </div>

                  </div>

                );
              })}

            </div>

          </div>

        )}

      </div>

    </div>
  );
}

export default Topology;