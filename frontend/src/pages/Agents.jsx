import { useCallback, useEffect, useState } from "react";
import API from "../api/client";

function Agents() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [enrollmentToken, setEnrollmentToken] = useState(null);

  const loadAgents = useCallback(async () => {
    try {
      const response = await API.get("/agents");
      setAgents(response.data.agents || []);
      setError("");
    } catch (err) {
      setError(err.response?.data?.error || "Unable to load collectors.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = setTimeout(() => {
      void loadAgents();
    }, 0);

    const interval = setInterval(() => {
      void loadAgents();
    }, 15000);

    return () => {
      clearTimeout(initialLoad);
      clearInterval(interval);
    };
  }, [loadAgents]);

  const createEnrollmentToken = async () => {
    try {
      const response = await API.post("/agent-enrollment-tokens", { ttl_minutes: 15 });
      setEnrollmentToken(response.data);
      setError("");
    } catch (err) {
      setError(err.response?.data?.error || "Unable to create an enrollment token.");
    }
  };

  return (
    <div>
      <div className="mb-8 flex items-start justify-between gap-6">
        <div>
          <h1 className="text-4xl font-bold">Collectors</h1>
          <p className="mt-2 text-slate-400">Authenticated network collectors and their real heartbeat state.</p>
        </div>
        <button onClick={createEnrollmentToken} className="rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-950">
          Create enrollment token
        </button>
      </div>

      {error && <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300">{error}</div>}

      {enrollmentToken && (
        <div className="mb-6 rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-5">
          <p className="font-semibold text-cyan-200">One-time collector enrollment token</p>
          <p className="mt-2 break-all font-mono text-sm">{enrollmentToken.enrollment_token}</p>
          <p className="mt-2 text-xs text-slate-400">Expires: {new Date(enrollmentToken.expires_at).toLocaleString()}</p>
          <p className="mt-3 text-sm text-slate-300">
            Put this value in NETWATCH_ENROLLMENT_TOKEN on the collector machine, run src/agent.py once, then remove it from the environment.
          </p>
        </div>
      )}

      {loading ? (
        <p className="text-slate-400">Loading collectors...</p>
      ) : agents.length === 0 ? (
        <div className="rounded-xl border border-white/10 bg-white/5 p-10 text-center text-slate-400">
          No collectors have been enrolled.
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-white/10 bg-white/5">
          <table className="w-full text-left">
            <thead className="border-b border-white/10 text-xs uppercase text-slate-500">
              <tr>
                <th className="p-4">Collector</th>
                <th className="p-4">Network</th>
                <th className="p-4">CIDR</th>
                <th className="p-4">Health</th>
                <th className="p-4">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.agent_id} className="border-b border-white/5 last:border-0">
                  <td className="p-4 font-mono text-xs">{agent.agent_id}</td>
                  <td className="p-4">{agent.network || "Unnamed"}</td>
                  <td className="p-4 font-mono text-sm">{agent.network_cidr || "Not set"}</td>
                  <td className="p-4"><StatusBadge status={agent.health_status} /></td>
                  <td className="p-4 text-sm text-slate-400">{agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }) {
  return (
    <span className="rounded-full border border-white/10 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-200">
      {status}
    </span>
  );
}

export default Agents;
