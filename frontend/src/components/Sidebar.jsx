import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="w-64 bg-white/5 border-r border-white/10 p-6">

      <h1 className="text-2xl text-cyan-400 font-bold mb-8">
        NetWatch
      </h1>

      <nav className="space-y-4 text-slate-300">

        <Link to="/">
          <p className="hover:text-white">Dashboard</p>
        </Link>

        <Link to="/agents">
          <p className="hover:text-white">Agents</p>
        </Link>

        <Link to="/intelligence">
          <p className="hover:text-white">Intelligence</p>
        </Link>

        <Link to="/topology">
          <p className="hover:text-white">Topology</p>
        </Link>

      </nav>

    </aside>
  );
}

export default Sidebar;