import { Link, useLocation } from "react-router-dom";

function MainLayout({ children }) {
  const location = useLocation();

  const navItem = (path, label) => {
    const active = location.pathname === path;

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
          NetWatch
        </h1>

        <nav className="space-y-2">

          {navItem("/", "Dashboard")}
          {navItem("/agents", "Agents")}
          {navItem("/intelligence", "Intelligence")}
          {navItem("/topology", "Topology")}

        </nav>

      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 p-8">
        {children}
      </main>

    </div>
  );
}

export default MainLayout;