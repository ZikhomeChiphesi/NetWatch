import { BrowserRouter, Routes, Route } from "react-router-dom";

import MainLayout from "./layout/MainLayout";

import Dashboard from "./pages/Dashboard";
import Agents from "./pages/Agents";
import Intelligence from "./pages/Intelligence";
import Topology from "./pages/Topology";

function App() {
  return (
    <BrowserRouter>

      <MainLayout>

        <Routes>

          <Route
            path="/"
            element={<Dashboard />}
          />

          <Route
            path="/agents"
            element={<Agents />}
          />

          <Route
            path="/intelligence"
            element={<Intelligence />}
          />

          <Route
            path="/topology"
            element={<Topology />}
          />

        </Routes>

      </MainLayout>

    </BrowserRouter>
  );
}

export default App;