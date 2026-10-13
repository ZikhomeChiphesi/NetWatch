import { useEffect, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import API from "../api/client";

function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  const [organizations, setOrganizations] = useState([]);
  const [selectedOrgId, setSelectedOrgId] = useState(
    localStorage.getItem("org_id") || ""
  );

  const userEmail = localStorage.getItem("user_email");

  useEffect(() => {
    const loadOrganizations = async () => {
      try {
        const response = await API.get("/auth/me");
        const orgs = response.data.organizations || [];

        setOrganizations(orgs);

        const currentOrgId = localStorage.getItem("org_id");

        const currentStillAllowed = orgs.some(
          (org) => org.org_id === currentOrgId
        );

        if (!currentStillAllowed && orgs.length > 0) {
          localStorage.setItem("org_id", orgs[0].org_id);
          setSelectedOrgId(orgs[0].org_id);
        }
      } catch (err) {
        console.error("Unable to load organizations", err);
      }
    };

    loadOrganizations();
  }, []);

  const switchOrganization = (event) => {
    const newOrgId = event.target.value;

    localStorage.setItem("org_id", newOrgId);
    setSelectedOrgId(newOrgId);

    // Reload so all API calls and WebSocket connections use the new tenant.
    window.location.assign("/");
  };

  const logout = async () => {
    try {
      await API.post("/auth/logout");
    } catch {
      // Clear the local session even if the server is unavailable.
    } finally {
      localStorage.removeItem("session_token");
      localStorage.removeItem("org_id");
      localStorage.removeItem("user_email");
      navigate("/login", { replace: true });
    }
  };

  const navItem = (path, label) => {
    const active =
      location.pathname === path ||
      (path !== "/" && location.pathname.startsWith(path));

    return (
      <Link
        to={path}
        className={`block rounded-lg px-3 py-2 transition ${
          active
            ? "bg-cyan-500/20 text-cyan-300"
            : "text-slate-400 hover:bg-white/5 hover:text-white"
        }`}
      >
        {label}
      </Link>
    );
  };

  return (
    <div className="flex min-h-screen bg-slate-950 text-white">
      <aside className="flex w-64 flex-col border-r border-slate-800 bg-slate-900 p-6">
        <div>
          <h1 className="text-2xl font-bold text-cyan-400">NetWatch SOC</h1>

          <p className="mt-4 text-xs uppercase tracking-wide text-slate-500">
            Organization
          </p>

          <select
            value={selectedOrgId}
            onChange={switchOrganization}
            className="mt-2 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500/60"
          >
            {organizations.map((org) => (
              <option key={org.org_id} value={org.org_id}>
                {org.name} ({org.org_id})
              </option>
            ))}
          </select>
        </div>

        <nav className="mt-8 space-y-2">
          {navItem("/", "Dashboard")}
          {navItem("/alerts", "Alerts")}
          {navItem("/agents", "Collectors")}
          {navItem("/intelligence", "Risk Intelligence")}
          {navItem("/topology", "Device Map")}
        </nav>

        <div className="mt-auto border-t border-slate-800 pt-6">
          <p className="truncate text-xs text-slate-500">{userEmail}</p>

          <button
            onClick={logout}
            className="mt-3 text-sm text-red-400 hover:text-red-300"
          >
            Logout
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}

export default MainLayout;