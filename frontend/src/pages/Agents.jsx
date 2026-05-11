import { useEffect, useState } from "react";
import API from "../services/api";

function Agents() {

  const [agents, setAgents] = useState([]);

  // =========================
  // FETCH AGENTS
  // =========================
  useEffect(() => {

    API.get("/agents")
      .then((res) => {
        setAgents(res.data);
      })
      .catch((err) => {
        console.error(err);
      });

  }, []);

  return (
    <div>

      {/* HEADER */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold">
          Agents
        </h1>

        <p className="text-slate-400 text-sm mt-1">
          Live monitoring agents connected to NetWatch
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
            "
          >

            <div className="flex justify-between items-center">

              {/* LEFT */}
              <div>

                <h2 className="text-lg font-semibold">
                  {agent.agent_id}
                </h2>

                <p className="text-slate-400 text-sm">
                  {agent.network}
                </p>

                <p className="text-slate-500 text-xs mt-1">
                  Last Seen: {agent.last_seen}
                </p>

              </div>

              {/* RIGHT */}
              <div className="flex items-center gap-2">

                <div
                  className={`
                    w-2 h-2 rounded-full
                    ${
                      agent.status === "online"
                        ? "bg-green-400 animate-pulse"
                        : "bg-red-400"
                    }
                  `}
                />

                <span
                  className={
                    agent.status === "online"
                      ? "text-green-400"
                      : "text-red-400"
                  }
                >
                  {agent.status}
                </span>

              </div>

            </div>

          </div>

        ))}

      </div>

    </div>
  );
}

export default Agents;