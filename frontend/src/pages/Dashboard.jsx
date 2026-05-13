import { useEffect, useState } from "react";
import { API } from "../api/client";
import { io } from "socket.io-client";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell
} from "recharts";

const socket = io("http://localhost:5000");

function Dashboard() {

  const [intel, setIntel] = useState(null);

  // =========================
  // LOAD INTEL
  // =========================
  const loadIntel = async () => {

    try {

      const res = await API.get("/intelligence");
      setIntel(res.data);

    } catch (err) {
      console.error(err);
    }
  };

  // =========================
  // LIVE SOCKETS
  // =========================
  useEffect(() => {

    loadIntel();

    const interval = setInterval(loadIntel, 5000);

    socket.on("device_update", loadIntel);
    socket.on("agent_update", loadIntel);

    return () => {
      clearInterval(interval);
      socket.disconnect();
    };

  }, []);

  // =========================
  // MOCK TREND DATA
  // =========================
  const trendData = [
    { time: "1m", risk: 12 },
    { time: "2m", risk: 18 },
    { time: "3m", risk: 24 },
    { time: "4m", risk: 15 },
    { time: "5m", risk: intel?.avg_risk || 0 }
  ];

  // =========================
  // PIE
  // =========================
  const pieData = [
    {
      name: "Trusted",
      value: Math.max(
        1,
        (intel?.device_count || 0) -
        (intel?.dangerous_devices || 0)
      )
    },
    {
      name: "Dangerous",
      value: intel?.dangerous_devices || 0
    }
  ];

  const COLORS = ["#22c55e", "#ef4444"];

  // =========================
  // BAR DATA
  // =========================
  const barData = [
    { name: "Low", value: 12 },
    { name: "Medium", value: 7 },
    { name: "High", value: intel?.dangerous_devices || 0 }
  ];

  return (
    <div>

      {/* ====================== */}
      {/* HEADER */}
      {/* ====================== */}
      <div className="mb-8">

        <h1 className="text-4xl font-bold text-white">
          Security Operations Center
        </h1>

        <p className="text-slate-400 mt-2">
          Enterprise Threat Intelligence & Network Visibility
        </p>

      </div>

      {/* ====================== */}
      {/* KPI CARDS */}
      {/* ====================== */}
      <div className="grid grid-cols-4 gap-6 mb-8">

        <div className="bg-white/5 border border-cyan-500/20 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Total Devices
          </p>

          <h2 className="text-4xl mt-2 font-bold text-cyan-400">
            {intel?.device_count || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-yellow-500/20 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Average Risk
          </p>

          <h2 className="text-4xl mt-2 font-bold text-yellow-400">
            {intel?.avg_risk?.toFixed(1) || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-red-500/20 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            Dangerous Devices
          </p>

          <h2 className="text-4xl mt-2 font-bold text-red-400">
            {intel?.dangerous_devices || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-green-500/20 rounded-2xl p-6">
          <p className="text-slate-400 text-sm">
            System Status
          </p>

          <h2 className="text-3xl mt-3 font-bold text-green-400">
            SECURE
          </h2>
        </div>

      </div>

      {/* ====================== */}
      {/* CHARTS */}
      {/* ====================== */}
      <div className="grid grid-cols-2 gap-6 mb-6">

        {/* RISK TREND */}
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 h-[340px]">

          <h2 className="text-xl mb-4 text-white">
            Threat Trend
          </h2>

          <ResponsiveContainer width="100%" height="90%">

            <LineChart data={trendData}>

              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />

              <Tooltip />

              <Line
                type="monotone"
                dataKey="risk"
                stroke="#06b6d4"
                strokeWidth={3}
              />

            </LineChart>

          </ResponsiveContainer>

        </div>

        {/* THREAT DISTRIBUTION */}
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 h-[340px]">

          <h2 className="text-xl mb-4 text-white">
            Threat Distribution
          </h2>

          <ResponsiveContainer width="100%" height="90%">

            <BarChart data={barData}>

              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />

              <Tooltip />

              <Bar
                dataKey="value"
                fill="#facc15"
              />

            </BarChart>

          </ResponsiveContainer>

        </div>

      </div>

      {/* ====================== */}
      {/* LOWER GRID */}
      {/* ====================== */}
      <div className="grid grid-cols-2 gap-6">

        {/* PIE */}
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 h-[380px]">

          <h2 className="text-xl mb-4">
            Device Reputation Ratio
          </h2>

          <ResponsiveContainer width="100%" height="90%">

            <PieChart>

              <Pie
                data={pieData}
                dataKey="value"
                outerRadius={120}
                label
              >

                {pieData.map((_, i) => (
                  <Cell
                    key={i}
                    fill={COLORS[i]}
                  />
                ))}

              </Pie>

              <Tooltip />

            </PieChart>

          </ResponsiveContainer>

        </div>

        {/* LIVE THREAT FEED */}
        <div className="bg-white/5 border border-red-500/20 rounded-2xl p-6 h-[380px] overflow-y-auto">

          <h2 className="text-xl mb-4 text-red-400">
            Live Threat Feed
          </h2>

          {!intel?.risky_devices?.length ? (

            <p className="text-slate-400">
              No active threats detected
            </p>

          ) : (

            intel.risky_devices.map((d, i) => (

              <div
                key={i}
                className="mb-4 p-4 bg-red-500/10 border border-red-500/20 rounded-xl"
              >

                <div className="flex justify-between">

                  <div>
                    <p className="font-semibold text-white">
                      {d.mac}
                    </p>

                    <p className="text-sm text-slate-400">
                      Reputation: {d.reputation}
                    </p>
                  </div>

                  <div className="text-red-400 font-bold">
                    {d.trust_score}
                  </div>

                </div>

              </div>

            ))

          )}

        </div>

      </div>

    </div>
  );
}

export default Dashboard;