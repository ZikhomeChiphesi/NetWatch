import { Link, useLocation, useNavigate, Outlet } from "react-router-dom";

function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem("api_key");
    navigate("/login");
  };

  const navItem = (path, label) => {
    const active =
      location.pathname === path ||
      (path !== "/" && location.pathname.startsWith(path));

    return (
      <Link
        to={path}
        className={`block px-3 py-2 rounded-lg transition ${
          active
            ? "bg-cyan-500/20 text-cyan-300"
            : "text-slate-400 hover:text-white"
        }`}
      >
        {label}
      </Link>
    );
  };

  return (
    <div className="flex min-h-screen bg-slate-950 text-white">

      {/* SIDEBAR */}
      <aside className="w-64 border-r border-slate-800 p-6 bg-slate-900">

        <h1 className="text-2xl font-bold text-cyan-400 mb-8">
          NetWatch SOC
        </h1>

        <nav className="space-y-2">
          {navItem("/", "Dashboard")}
          {navItem("/agents", "Agents")}
          {navItem("/intelligence", "Intelligence")}
          {navItem("/topology", "Topology")}
        </nav>

        {/* AUTH */}
        <div className="mt-10 pt-6 border-t border-slate-800">
          <button
            onClick={logout}
            className="text-red-400 hover:text-red-300"
          >
            Logout
          </button>
        </div>

      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 p-8">
        <Outlet />
      </main>

    </div>
  );
}

export default MainLayout;