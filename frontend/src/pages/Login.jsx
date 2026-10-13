import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import API from "../api/client";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const login = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await API.post("/auth/login", { email, password });
      const data = response.data;

      localStorage.setItem("session_token", data.token);
      localStorage.setItem("org_id", data.default_org_id);
      localStorage.setItem("user_email", data.user.email);

      navigate("/", { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || "Unable to log in.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-white">
      <form
        onSubmit={login}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-white/5 p-8"
      >
        <h1 className="text-3xl font-bold text-cyan-400">NetWatch</h1>
        <p className="mt-2 text-slate-400">Sign in to your organization.</p>

        {error && (
          <div className="mt-5 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <label className="mt-6 block text-sm text-slate-300">Email</label>
        <input
          type="email"
          required
          autoComplete="email"
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3 outline-none focus:border-cyan-500/60"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />

        <label className="mt-4 block text-sm text-slate-300">Password</label>
        <input
          type="password"
          required
          autoComplete="current-password"
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3 outline-none focus:border-cyan-500/60"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <button
          type="submit"
          disabled={loading}
          className="mt-6 w-full rounded-lg bg-cyan-500 py-3 font-bold text-slate-950 disabled:opacity-50"
        >
          {loading ? "Signing in..." : "Sign in"}
        </button>

        <p className="mt-5 text-center text-sm text-slate-400">
          Need an organization?{" "}
          <Link to="/register" className="text-cyan-300 hover:text-cyan-200">
            Create one
          </Link>
        </p>
      </form>
    </div>
  );
}

export default Login;
