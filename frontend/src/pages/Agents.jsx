import { useEffect, useState } from "react";
import { API } from "../api/client";
import { io } from "socket.io-client";

const socket = io("http://localhost:5000");

function Agents() {

  const [agents, setAgents] = useState([]);

  // =========================
  // FETCH AGENTS
  // =========================
  const loadAgents = async () => {
    try {
      const res = await API.get("/agents");
      setAgents(res.data);
    } catch (err) {
      console.error("Agent fetch error:", err);
    }
  };

  // =========================
  // LIVE UPDATES
  // =========================
  useEffect(() => {

    loadAgents();

    const interval = setInterval(loadAgents, 5000);

    // REAL-TIME SOCKET EVENTS
    socket.on("agent_update", () => {
      loadAgents();
    });

    return () => {
      clearInterval(interval);
      socket.disconnect();
    };

  }, []);

  return (
    <div>

      {/* HEADER */}
      <div className="mb-6">

        <h1 className="text-3xl font-bold text-white">
          Agents
        </h1>

        <p className="text-slate-400 text-sm mt-1">
          Live security agents monitoring network activity
        </p>

      </div>

      {/* AGENT LIST */}
      <div className="space-y-4">

        {agents.map((agent) => (

          <div
            key={agent.agent_id}
            className="
              bg-white/5
              border border-white/10
              backdrop-blur-md
              rounded-xl
              p-5
              flex justify-between items-center
            "
          >

            {/* LEFT */}
            <div>

              <h2 className="text-lg font-semibold text-white">
                {agent.agent_id}
              </h2>

              <p className="text-slate-400 text-sm">
                Network: {agent.network}
              </p>

              <p className="text-slate-500 text-xs mt-1">
                Last Seen: {agent.last_seen}
              </p>

            </div>

            {/* RIGHT - STATUS */}
            <div className="flex items-center gap-2">

              {/* STATUS DOT */}
              <div
                className={`
                  w-2.5 h-2.5 rounded-full
                  ${
                    agent.status === "online"
                      ? "bg-green-400 animate-pulse"
                      : "bg-red-400"
                  }
                `}
              />

              {/* STATUS TEXT */}
              <span
                className={
                  agent.status === "online"
                    ? "text-green-400 font-medium"
                    : "text-red-400 font-medium"
                }
              >
                {agent.status.toUpperCase()}
              </span>

            </div>

          </div>

        ))}

      </div>

    </div>
  );
}

export default Agents;