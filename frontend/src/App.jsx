import { useEffect, useState } from "react";
import axios from "axios";
import { io } from "socket.io-client";

const socket = io("http://localhost:5000");

function App() {
  const [agents, setAgents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [intel, setIntel] = useState(null);

  const loadAgents = async () => {
    const res = await axios.get("http://localhost:5000/agents");
    setAgents(res.data);
  };

  const loadIntel = async () => {
    const res = await axios.get("http://localhost:5000/intelligence");
    setIntel(res.data);
  };

  useEffect(() => {
    loadAgents();
    loadIntel();

    // LIVE AGENTS
    socket.on("agent_status", (data) => {
      setAgents(prev =>
        prev.map(a =>
          a.agent_id === data.agent_id
            ? { ...a, status: data.status }
            : a
        )
      );
    });

    // SECURITY ALERTS
    socket.on("security_alert", (data) => {
      setAlerts(prev => [data, ...prev]);
    });

    // DEVICE UPDATES → refresh intelligence
    socket.on("device_update", () => {
      loadIntel();
    });

    return () => socket.disconnect();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-white p-6">

      <h1 className="text-3xl text-cyan-400 mb-6">
        NetWatch Intelligence Layer
      </h1>

      {/* ===================== */}
      {/* INTELLIGENCE CARDS */}
      {/* ===================== */}
      <div className="grid grid-cols-2 gap-4 mb-6">

        <div className="bg-slate-800 p-4 rounded">
          <h2 className="text-xl">High Risk Devices</h2>
          <p className="text-yellow-400 text-2xl">
            {intel?.high_risk_count || 0}
          </p>
        </div>

        <div className="bg-slate-800 p-4 rounded">
          <h2 className="text-xl">Agents Online</h2>
          <p className="text-green-400 text-2xl">
            {agents.filter(a => a.status === "online").length}
          </p>
        </div>

      </div>

      {/* ===================== */}
      {/* ALERTS */}
      {/* ===================== */}
      <div className="bg-red-900/20 border border-red-500 p-4 rounded mb-6">
        <h2 className="text-red-400 mb-2">Live Security Alerts</h2>

        {alerts.length === 0 && (
          <p className="text-slate-400">No alerts</p>
        )}

        {alerts.map((a, i) => (
          <div key={i}>
            ⚠ {a.type} | IP: {a.ip} | Score: {a.score}
          </div>
        ))}
      </div>

      {/* ===================== */}
      {/* AGENTS */}
      {/* ===================== */}
      <div>
        <h2 className="text-2xl mb-4">Agents</h2>

        {agents.map(a => (
          <div key={a.agent_id} className="bg-slate-800 p-3 mb-2 rounded flex justify-between">

            <div>
              <div>{a.agent_id}</div>
              <div className="text-sm text-slate-400">{a.network}</div>
            </div>

            <div className={
              a.status === "online"
                ? "text-green-400"
                : "text-red-400"
            }>
              {a.status}
            </div>

          </div>
        ))}
      </div>

    </div>
  );
}

export default App;