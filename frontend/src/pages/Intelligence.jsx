import { useEffect, useState } from "react";
import { API } from "../api/client";

function Intelligence() {

  const [intel, setIntel] = useState(null);

  // =========================
  // LOAD INTELLIGENCE
  // =========================
  const loadIntel = async () => {
    try {
      const res = await API.get("/intelligence");
      setIntel(res.data);
    } catch (err) {
      console.error("Intel fetch failed:", err);
    }
  };

  useEffect(() => {

    loadIntel();

    const interval = setInterval(loadIntel, 5000);

    return () => clearInterval(interval);

  }, []);

  return (
    <div>

      {/* HEADER */}
      <div className="mb-6">

        <h1 className="text-3xl font-bold text-white">
          Intelligence Center
        </h1>

        <p className="text-slate-400 text-sm mt-1">
          Threat detection, anomaly scoring & network insights
        </p>

      </div>

      {/* =========================
          SUMMARY CARDS
      ========================= */}
      <div className="grid grid-cols-3 gap-4 mb-6">

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">Device Count</p>
          <p className="text-3xl font-bold text-cyan-400">
            {intel?.device_count || 0}
          </p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">Average Risk</p>
          <p className="text-3xl font-bold text-yellow-400">
            {intel?.avg_risk?.toFixed(2) || 0}
          </p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-5">
          <p className="text-slate-400 text-sm">Active Threats</p>
          <p className="text-3xl font-bold text-red-400">
            {intel?.anomalies?.length || 0}
          </p>
        </div>

      </div>

      {/* =========================
          THREAT PANEL
      ========================= */}
      <div className="bg-white/5 border border-white/10 rounded-xl p-6">

        <h2 className="text-xl font-semibold text-white mb-4">
          Threat Intelligence Feed
        </h2>

        {!intel?.anomalies?.length ? (
          <p className="text-slate-400">
            System stable — no anomalies detected
          </p>
        ) : (
          <div className="space-y-3">

            {intel.anomalies.map((a, i) => (

              <div
                key={i}
                className="
                  bg-red-500/10
                  border border-red-500/20
                  rounded-lg
                  p-3
                "
              >

                <p className="text-red-300 text-sm">
                  ⚠ {a}
                </p>

              </div>

            ))}

          </div>
        )}

      </div>

      {/* =========================
          INTELLIGENCE NOTES
      ========================= */}
      <div className="mt-6 text-slate-400 text-sm">

        <p>
          • Risk score is derived from device anomalies and network changes
        </p>

        <p>
          • Unknown devices significantly increase threat score
        </p>

        <p>
          • System updates every 5 seconds from backend intelligence engine
        </p>

      </div>

    </div>
  );
}

export default Intelligence;