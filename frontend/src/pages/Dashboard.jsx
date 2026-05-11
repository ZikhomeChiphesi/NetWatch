import { useEffect, useState } from "react";
import API from "../services/api";

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

  // =========================
  // LOAD INTELLIGENCE
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
  // AUTO REFRESH
  // =========================
  useEffect(() => {

    loadIntel();

    const interval = setInterval(loadIntel, 5000);

    return () => clearInterval(interval);

  }, []);

  // =========================
  // MOCK TREND DATA
  // =========================
  const trendData = [
    { time: "1m", risk: 12 },
    { time: "2m", risk: 18 },
    { time: "3m", risk: 10 },
    { time: "4m", risk: 26 },
    { time: "5m", risk: intel?.avg_risk || 0 }
  ];

  // =========================
  // THREAT DISTRIBUTION
  // =========================
  const barData = [
    { name: "LOW", value: 18 },
    { name: "MED", value: 9 },
    { name: "HIGH", value: 4 }
  ];

  // =========================
  // SEVERITY PIE
  // =========================
  const pieData = [
    { name: "Normal", value: 75 },
    { name: "Threat", value: 25 }
  ];

  const COLORS = ["#22c55e", "#ef4444"];

  return (
    <div>

      {/* ===================== */}
      {/* PAGE HEADER */}
      {/* ===================== */}
      <div className="mb-8">

        <h1 className="text-4xl font-bold text-white">
          NetWatch Dashboard
        </h1>

        <p className="text-slate-400 mt-2">
          Real-time observability & intelligence analytics
        </p>

      </div>

      {/* ===================== */}
      {/* STAT CARDS */}
      {/* ===================== */}
      <div className="grid grid-cols-3 gap-6 mb-8">

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <p className="text-slate-400 text-sm">
            Device Count
          </p>

          <h2 className="text-4xl mt-2 font-bold text-cyan-400">
            {intel?.device_count || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <p className="text-slate-400 text-sm">
            Average Risk
          </p>

          <h2 className="text-4xl mt-2 font-bold text-yellow-400">
            {intel?.avg_risk?.toFixed(2) || 0}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-md">
          <p className="text-slate-400 text-sm">
            Active Anomalies
          </p>

          <h2 className="text-4xl mt-2 font-bold text-red-400">
            {intel?.anomalies?.length || 0}
          </h2>
        </div>

      </div>

      {/* ===================== */}
      {/* CHARTS GRID */}
      {/* ===================== */}
      <div className="grid grid-cols-2 gap-6">

        {/* ===================== */}
        {/* LINE CHART */}
        {/* ===================== */}
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 h-[350px]">

          <h2 className="text-xl mb-4">
            Risk Trend
          </h2>

          <ResponsiveContainer width="100%" height="90%">

            <LineChart data={trendData}>

              <XAxis dataKey="time" />

              <YAxis />

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

        {/* ===================== */}
        {/* BAR CHART */}
        {/* ===================== */}
        <div className="bg-white/5 border border-white/10 rounded-2xl p-6 h-[350px]">

          <h2 className="text-xl mb-4">
            Threat Distribution
          </h2>

          <ResponsiveContainer width="100%" height="90%">

            <BarChart data={barData}>

              <XAxis dataKey="name" />

              <YAxis />

              <Tooltip />

              <Bar
                dataKey="value"
                fill="#facc15"
              />

            </BarChart>

          </ResponsiveContainer>

        </div>

      </div>

      {/* ===================== */}
      {/* PIE CHART */}
      {/* ===================== */}
      <div className="mt-6 bg-white/5 border border-white/10 rounded-2xl p-6 h-[400px]">

        <h2 className="text-xl mb-4">
          Threat Severity Ratio
        </h2>

        <ResponsiveContainer width="100%" height="90%">

          <PieChart>

            <Pie
              data={pieData}
              dataKey="value"
              outerRadius={130}
              label
            >

              {pieData.map((entry, index) => (
                <Cell
                  key={index}
                  fill={COLORS[index % COLORS.length]}
                />
              ))}

            </Pie>

            <Tooltip />

          </PieChart>

        </ResponsiveContainer>

      </div>

    </div>
  );
}

export default Dashboard;