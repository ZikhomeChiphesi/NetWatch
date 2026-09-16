import { useEffect, useState } from "react";
import axios from "axios";

const API_URL = "http://localhost:5000";

function Agents() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadAgents = async () => {
    try {
      setLoading(true);
      setError("");

      const orgId = localStorage.getItem("org_id");

      if (!orgId) {
        throw new Error("Organization ID is missing. Please log in again.");
      }

      const response = await axios.get(`${API_URL}/agents`, {
        headers: {
          "X-ORG-ID": orgId,
        },
      });

      const data = response.data;

      // Backend returns { agents: [...] }
      setAgents(Array.isArray(data) ? data : data.agents || []);
    } catch (err) {
      console.error("Agents error:", err);

      setError(
        err.response?.data?.error ||
          err.message ||
          "Unable to load agents."
      );

      setAgents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAgents();

    const interval = setInterval(loadAgents, 10000);

    return () => clearInterval(interval);
  }, []);

  const formatDate = (value) => {
    if (!value) return "Never";

    try {
      return new Date(value).toLocaleString();
    } catch {
      return value;
    }
  };

  return (
    <div className="min-h-full">

      {/* HEADER */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white">
              Security Agents
            </h1>

            <p className="text-slate-400 mt-2">
              Connected NetWatch monitoring agents
            </p>
          </div>

          <button
            onClick={loadAgents}
            className="px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 transition"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* SUMMARY */}
      <div className="grid grid-cols-3 gap-6 mb-8">

        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm">
            Total Agents
          </p>

          <h2 className="text-4xl font-bold text-cyan-400 mt-2">
            {agents.length}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm">
            Monitoring Status
          </p>

          <h2 className="text-2xl font-bold text-emerald-400 mt-3">
            {agents.length > 0 ? "ACTIVE" : "WAITING"}
          </h2>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6">
          <p className="text-slate-400 text-sm">
            Data Source
          </p>

          <h2 className="text-2xl font-bold text-white mt-3">
            NetWatch Agents
          </h2>
        </div>

      </div>

      {/* ERROR */}
      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300">
          <p className="font-semibold">
            Agent data unavailable
          </p>

          <p className="text-sm mt-1">
            {error}
          </p>
        </div>
      )}

      {/* LOADING */}
      {loading && (
        <div className="bg-white/5 border border-white/10 rounded-xl p-10 text-center">
          <p className="text-slate-400">
            Loading security agents...
          </p>
        </div>
      )}

      {/* AGENTS */}
      {!loading && !error && (
        <div className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">

          <div className="p-5 border-b border-white/10">
            <div className="flex items-center justify-between">

              <div>
                <h2 className="text-xl font-semibold text-white">
                  Registered Agents
                </h2>

                <p className="text-sm text-slate-500 mt-1">
                  Agents reporting network telemetry to NetWatch
                </p>
              </div>

              <div className="text-sm text-cyan-300">
                {agents.length} agent{agents.length !== 1 ? "s" : ""}
              </div>

            </div>
          </div>

          {agents.length === 0 ? (
            <div className="p-12 text-center">
              <div className="text-5xl mb-4">
                ◉
              </div>

              <h3 className="text-xl text-white">
                No agents found
              </h3>

              <p className="text-slate-400 mt-2">
                NetWatch is waiting for monitoring agents.
              </p>
            </div>
          ) : (

            <div className="divide-y divide-white/5">

              {agents.map((agent, index) => (

                <div
                  key={agent.agent_id || index}
                  className="p-5 hover:bg-white/5 transition"
                >

                  <div className="flex items-center justify-between">

                    <div className="flex items-center gap-4">

                      {/* STATUS */}
                      <div className="relative">
                        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                          <span className="w-3 h-3 rounded-full bg-emerald-400"></span>
                        </div>
                      </div>

                      {/* DETAILS */}
                      <div>
                        <p className="text-white font-semibold">
                          NetWatch Agent {index + 1}
                        </p>

                        <p className="font-mono text-xs text-slate-500 mt-1">
                          {agent.agent_id}
                        </p>
                      </div>

                    </div>

                    {/* RIGHT */}
                    <div className="text-right">

                      <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
                        <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                        ACTIVE
                      </div>

                      <p className="text-xs text-slate-500 mt-2">
                        Last seen: {formatDate(agent.last_seen)}
                      </p>

                    </div>

                  </div>

                  {/* NETWORK */}
                  <div className="mt-4 ml-16">

                    <div className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800">

                      <span className="text-slate-500 text-xs">
                        NETWORK
                      </span>

                      <span className="text-cyan-300 font-mono text-sm">
                        {agent.network || "Unknown network"}
                      </span>

                    </div>

                  </div>

                </div>

              ))}

            </div>

          )}

        </div>
      )}

    </div>
  );
}

export default Agents;