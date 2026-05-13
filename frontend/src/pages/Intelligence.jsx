import { useEffect, useState } from "react";
import { API } from "../api/client";

function Intelligence() {

  const [intel, setIntel] = useState(null);

  // =========================
  // LOAD
  // =========================
  useEffect(() => {

    API.get("/intelligence")
      .then((res) => {
        setIntel(res.data);
      })
      .catch(console.error);

  }, []);

  return (
    <div>

      {/* HEADER */}
      <div className="mb-8">

        <h1 className="text-4xl font-bold text-white">
          Threat Intelligence
        </h1>

        <p className="text-slate-400 mt-2">
          Reputation analysis and network anomaly monitoring
        </p>

      </div>

      {/* OVERVIEW */}
      <div className="grid grid-cols-3 gap-6 mb-8">

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Average Risk
          </p>

          <h2 className="text-4xl font-bold mt-2 text-yellow-400">
            {intel?.avg_risk?.toFixed(1) || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Dangerous Devices
          </p>

          <h2 className="text-4xl font-bold mt-2 text-red-400">
            {intel?.dangerous_devices || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Devices Monitored
          </p>

          <h2 className="text-4xl font-bold mt-2 text-cyan-400">
            {intel?.device_count || 0}
          </h2>
        </div>

      </div>

      {/* RISK TABLE */}
      <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">

        <div className="p-5 border-b border-white/10">

          <h2 className="text-xl text-white">
            Suspicious Devices
          </h2>

        </div>

        <table className="w-full">

          <thead className="bg-white/5">

            <tr className="text-left text-slate-400 text-sm">

              <th className="p-4">MAC</th>
              <th className="p-4">Trust Score</th>
              <th className="p-4">Reputation</th>

            </tr>

          </thead>

          <tbody>

            {intel?.risky_devices?.map((d, i) => (

              <tr
                key={i}
                className="border-t border-white/5"
              >

                <td className="p-4 font-mono text-sm">
                  {d.mac}
                </td>

                <td className="p-4 text-red-400">
                  {d.trust_score}
                </td>

                <td className="p-4">

                  <span className="
                    px-3 py-1 rounded-full
                    bg-red-500/20
                    text-red-400
                    text-sm
                  ">
                    {d.reputation}
                  </span>

                </td>

              </tr>

            ))}

          </tbody>

        </table>

      </div>

    </div>
  );
}

export default Intelligence;