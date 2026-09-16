import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { API } from "../api/client";

function Login() {

  const [email, setEmail] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [orgId, setOrgId] = useState("");

  const navigate = useNavigate();

  const login = async () => {
    try {

      // For Phase 10 MVP:
      // we simulate login using api key + org id
      localStorage.setItem("api_key", apiKey);
      localStorage.setItem("org_id", orgId);

      navigate("/");

    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-slate-950 text-white">

      <div className="w-96 bg-white/5 p-6 rounded-xl border border-white/10">

        <h1 className="text-2xl font-bold mb-4">
          NetWatch Login
        </h1>

        <input
          className="w-full mb-3 p-2 bg-slate-900 rounded"
          placeholder="Org ID"
          value={orgId}
          onChange={(e) => setOrgId(e.target.value)}
        />

        <input
          className="w-full mb-3 p-2 bg-slate-900 rounded"
          placeholder="API Key"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />

        <button
          onClick={login}
          className="w-full bg-cyan-500 py-2 rounded font-bold"
        >
          Login
        </button>

      </div>

    </div>
  );
}

export default Login;