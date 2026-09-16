import { useEffect, useState } from "react";

function Intelligence() {
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadIntelligence = async () => {
      try {
        setLoading(true);
        setError("");

        const orgId = localStorage.getItem("org_id");

        if (!orgId) {
          throw new Error("No organization ID found in localStorage.");
        }

        const response = await fetch("http://localhost:5000/intelligence", {
          method: "GET",
          headers: {
            "X-ORG-ID": orgId,
          },
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(
            `Backend returned ${response.status}: ${text}`
          );
        }

        const data = await response.json();

        console.log("NETWATCH INTELLIGENCE DATA:", data);

        setIntel(data);
      } catch (err) {
        console.error("INTELLIGENCE PAGE ERROR:", err);
        setError(err.message || "Failed to load intelligence data.");
      } finally {
        setLoading(false);
      }
    };

    loadIntelligence();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen text-white">
        <h1 className="text-4xl font-bold text-white">
          Threat Intelligence
        </h1>

        <p className="text-slate-400 mt-2">
          Loading network intelligence...
        </p>

        <div className="mt-8 bg-white/5 border border-white/10 rounded-xl p-8">
          <p className="text-cyan-400">
            Connecting to NetWatch Security API...
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen text-white">
        <h1 className="text-4xl font-bold text-white">
          Threat Intelligence
        </h1>

        <p className="text-slate-400 mt-2">
          Reputation analysis and anomaly detection engine
        </p>

        <div className="mt-8 bg-red-500/10 border border-red-500/30 rounded-xl p-6">
          <h2 className="text-xl font-semibold text-red-400">
            Intelligence API Error
          </h2>

          <p className="text-slate-300 mt-3 break-words">
            {error}
          </p>

          <button
            onClick={() => window.location.reload()}
            className="mt-5 px-4 py-2 bg-cyan-500 text-black rounded-lg font-semibold hover:bg-cyan-400"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const avgRisk = Number(intel?.avg_risk || 0);
  const dangerousDevices = Number(intel?.dangerous_devices || 0);
  const deviceCount = Number(intel?.device_count || 0);
  const riskyDevices = Array.isArray(intel?.risky_devices)
    ? intel.risky_devices
    : [];

  return (
    <div className="min-h-screen text-white">

      {/* HEADER */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-white">
          Threat Intelligence
        </h1>

        <p className="text-slate-400 mt-2">
          Reputation analysis and anomaly detection engine
        </p>
      </div>

      {/* STATUS */}
      <div className="mb-6 bg-cyan-500/10 border border-cyan-500/20 rounded-xl px-5 py-3">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-green-400"></div>

          <span className="text-slate-300">
            NetWatch intelligence engine online
          </span>

          <span className="text-cyan-400 ml-auto">
            {deviceCount} active devices
          </span>
        </div>
      </div>

      {/* KPI CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">

        {/* AVG RISK */}
        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm uppercase tracking-wide">
            Average Risk
          </p>

          <h2 className="text-5xl font-bold text-yellow-400 mt-3">
            {avgRisk.toFixed(1)}
          </h2>

          <p className="text-slate-500 mt-2">
            Network-wide risk score
          </p>
        </div>

        {/* DANGEROUS */}
        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm uppercase tracking-wide">
            Dangerous Devices
          </p>

          <h2 className="text-5xl font-bold text-red-400 mt-3">
            {dangerousDevices}
          </h2>

          <p className="text-slate-500 mt-2">
            Devices requiring attention
          </p>
        </div>

        {/* DEVICES */}
        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm uppercase tracking-wide">
            Devices Detected
          </p>

          <h2 className="text-5xl font-bold text-cyan-400 mt-3">
            {deviceCount}
          </h2>

          <p className="text-slate-500 mt-2">
            Current network inventory
          </p>
        </div>

      </div>

      {/* RISKY DEVICES */}
      <div className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">

        <div className="p-5 border-b border-white/10">
          <div className="flex items-center justify-between">

            <div>
              <h2 className="text-xl font-semibold text-white">
                Highest-Risk Devices
              </h2>

              <p className="text-slate-500 text-sm mt-1">
                Devices with the lowest trust scores
              </p>
            </div>

            <div className="text-sm text-slate-400">
              Top {riskyDevices.length}
            </div>

          </div>
        </div>

        {riskyDevices.length === 0 ? (

          <div className="p-8 text-center">
            <p className="text-slate-400">
              No risky devices detected.
            </p>
          </div>

        ) : (

          <div className="overflow-x-auto">

            <table className="w-full">

              <thead>
                <tr className="text-left text-slate-400 text-sm border-b border-white/10">

                  <th className="p-4">
                    #
                  </th>

                  <th className="p-4">
                    MAC Address
                  </th>

                  <th className="p-4">
                    Trust Score
                  </th>

                  <th className="p-4">
                    Reputation
                  </th>

                </tr>
              </thead>

              <tbody>

                {riskyDevices.map((device, index) => {

                  const trust = Number(device?.trust_score || 0);

                  const reputation =
                    device?.reputation || "UNKNOWN";

                  return (
                    <tr
                      key={`${device?.mac || "device"}-${index}`}
                      className="border-t border-white/5 hover:bg-white/5"
                    >

                      <td className="p-4 text-slate-500">
                        {index + 1}
                      </td>

                      <td className="p-4 font-mono text-sm text-slate-200">
                        {device?.mac || "Unknown"}
                      </td>

                      <td className="p-4">

                        <span
                          className={
                            trust < 25
                              ? "text-red-400 font-bold"
                              : trust < 50
                              ? "text-orange-400 font-semibold"
                              : "text-yellow-400"
                          }
                        >
                          {trust}
                        </span>

                      </td>

                      <td className="p-4">

                        <span
                          className={
                            reputation === "DANGEROUS"
                              ? "text-red-400 font-semibold"
                              : reputation === "SUSPICIOUS"
                              ? "text-orange-400 font-semibold"
                              : reputation === "NORMAL"
                              ? "text-yellow-400"
                              : "text-green-400"
                          }
                        >
                          {reputation}
                        </span>

                      </td>

                    </tr>
                  );
                })}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </div>
  );
}

export default Intelligence;