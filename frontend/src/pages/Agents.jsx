import { useEffect, useState } from "react";
import axios from "axios";

function Agents() {
  const [agents, setAgents] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:5000/agents")
      .then(res => setAgents(res.data));
  }, []);

  return (
    <div className="p-8 bg-slate-950 min-h-screen text-white">
      <h1 className="text-3xl mb-6">Agents</h1>

      {agents.map(a => (
        <div key={a.agent_id} className="bg-slate-800 p-4 mb-3 rounded">
          <div><b>ID:</b> {a.agent_id}</div>
          <div><b>Network:</b> {a.network}</div>
          <div><b>Status:</b> {a.status}</div>
          <div><b>Last Seen:</b> {a.last_seen}</div>
        </div>
      ))}
    </div>
  );
}

export default Agents;