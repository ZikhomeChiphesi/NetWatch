import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import API from "../api/client";

function Register() {
  const [orgName, setOrgName] = useState("");
  const [orgId, setOrgId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const register = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await API.post("/auth/register", {
        org_name: orgName,
        org_id: orgId || undefined,
        email,
        password,
      });

      const data = response.data;
      localStorage.setItem("session_token", data.token);
      localStorage.setItem("org_id", data.organization.org_id);
      localStorage.setItem("user_email", data.user.email);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || "Unable to create the organization.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-white">
      <form
        onSubmit={register}
        className="w-full max-w-lg rounded-2xl border border-white/10 bg-white/5 p-8"
      >
        <h1 className="text-3xl font-bold text-cyan-400">Create NetWatch organization</h1>
        <p className="mt-2 text-slate-400">
          This creates the first owner account. Collector enrollment happens separately after login.
        </p>

        {error && (
          <div className="mt-5 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <label className="mt-6 block text-sm text-slate-300">Organization name</label>
        <input
          required
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3"
          value={orgName}
          onChange={(event) => setOrgName(event.target.value)}
          placeholder="University Network Lab"
        />

        <label className="mt-4 block text-sm text-slate-300">Organization ID (optional)</label>
        <input
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3 font-mono"
          value={orgId}
          onChange={(event) => setOrgId(event.target.value)}
          placeholder="UNZA-LAB"
        />

        <label className="mt-4 block text-sm text-slate-300">Owner email</label>
        <input
          type="email"
          required
          autoComplete="email"
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />

        <label className="mt-4 block text-sm text-slate-300">Password</label>
        <input
          type="password"
          required
          minLength={12}
          autoComplete="new-password"
          className="mt-2 w-full rounded-lg border border-white/10 bg-slate-900 p-3"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="At least 12 characters"
        />

        <button
          type="submit"
          disabled={loading}
          className="mt-6 w-full rounded-lg bg-cyan-500 py-3 font-bold text-slate-950 disabled:opacity-50"
        >
          {loading ? "Creating..." : "Create organization"}
        </button>

        <p className="mt-5 text-center text-sm text-slate-400">
          Already registered?{" "}
          <Link to="/login" className="text-cyan-300 hover:text-cyan-200">
            Sign in
          </Link>
        </p>
      </form>
    </div>
  );
}

export default Register;
