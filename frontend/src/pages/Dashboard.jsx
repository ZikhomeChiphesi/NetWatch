import { useEffect, useState } from "react";
import { API } from "../api/client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from "recharts";

function Dashboard() {

  const [intel, setIntel] = useState(null);

  const loadIntel = async () => {
    try {
      const res = await API.get("/intelligence");
      setIntel(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadIntel();
    const interval = setInterval(loadIntel, 4000);
    return () => clearInterval(interval);
  }, []);

  // =========================
  // REAL DERIVED DATA
  // =========================

  const anomalies = intel?.anomalies || [];

  const severityCounts = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0
  };

  anomalies.forEach(a => {
    if (a.level === "LOW") severityCounts.LOW++;
    if (a.level === "MEDIUM") severityCounts.MEDIUM++;
    if (a.level === "HIGH") severityCounts.HIGH++;
  });

  const barData = [
    { name: "LOW", value: severityCounts.LOW },
    { name: "MED", value: severityCounts.MEDIUM },
    { name: "HIGH", value: severityCounts.HIGH }
  ];

  const pieData = [
    { name: "Safe", value: (intel?.device_count || 0) - anomalies.length },
    { name: "Threat", value: anomalies.length }
  ];

  const trendData = [
    { time: "Now", risk: intel?.avg_risk || 0 }
  ];

  const COLORS = ["#22c55e", "#ef4444"];

  return (
    <div>

      {/* HEADER */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-white">
          NetWatch Intelligence Dashboard
        </h1>

        <p className="text-slate-400 mt-2">
          Real-time security + anomaly detection engine
        </p>
      </div>

      {/* STATS */}
      <div className="grid grid-cols-3 gap-6 mb-8">

        <div className="bg-white/5 p-6 rounded-xl">
          <p className="text-slate-400">Devices</p>
          <h2 className="text-3xl text-cyan-400">
            {intel?.device_count || 0}
          </h2>
        </div>

        <div className="bg-white/5 p-6 rounded-xl">
          <p className="text-slate-400">Avg Risk</p>
          <h2 className="text-3xl text-yellow-400">
            {intel?.avg_risk?.toFixed(2) || 0}
          </h2>
        </div>

        <div className="bg-white/5 p-6 rounded-xl">
          <p className="text-slate-400">Threats</p>
          <h2 className="text-3xl text-red-400">
            {anomalies.length}
          </h2>
        </div>

      </div>

      {/* CHARTS */}
      <div className="grid grid-cols-2 gap-6">

        {/* BAR */}
        <div className="bg-white/5 p-6 rounded-xl h-[350px]">
          <h2 className="mb-4">Threat Levels</h2>

          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={barData}>
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#facc15" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* LINE */}
        <div className="bg-white/5 p-6 rounded-xl h-[350px]">
          <h2 className="mb-4">Risk Snapshot</h2>

          <ResponsiveContainer width="100%" height="90%">
            <LineChart data={trendData}>
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line dataKey="risk" stroke="#06b6d4" />
            </LineChart>
          </ResponsiveContainer>
        </div>

      </div>

      {/* PIE */}
      <div className="mt-6 bg-white/5 p-6 rounded-xl h-[350px]">
        <h2 className="mb-4">System Health</h2>

        <ResponsiveContainer width="100%" height="90%">
          <PieChart>
            <Pie data={pieData} dataKey="value" outerRadius={120} label>
              {pieData.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
}

export default Dashboard;