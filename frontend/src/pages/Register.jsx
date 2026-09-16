import { useState } from "react";
import API from "../api/client";
import { useNavigate } from "react-router-dom";

function Register() {
  const [network, setNetwork] = useState("");
  const [result, setResult] = useState(null);

  const navigate = useNavigate();

  const handleRegister = async () => {
    try {
      const res = await API.post("/register", { network });

      setResult(res.data);

      // auto-login after register
      localStorage.setItem("api_key", res.data.api_key);

      setTimeout(() => {
        navigate("/");
      }, 1000);

    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0B1220] text-white">
      <div className="bg-white/5 border border-white/10 p-8 rounded-xl w-[400px]">

        <h1 className="text-2xl mb-4 text-yellow-400">Register Network</h1>

        <input
          className="w-full p-2 mb-4 bg-black/40 border border-white/10 rounded"
          placeholder="Network name"
          value={network}
          onChange={(e) => setNetwork(e.target.value)}
        />

        <button
          onClick={handleRegister}
          className="w-full bg-yellow-500 hover:bg-yellow-600 p-2 rounded"
        >
          Register
        </button>

        {result && (
          <div className="mt-4 text-sm text-green-400">
            API Key Generated ✔
          </div>
        )}

      </div>
    </div>
  );
}

export default Register;