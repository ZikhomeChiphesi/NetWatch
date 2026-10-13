import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import MainLayout from "./layout/MainLayout";
import Agents from "./pages/Agents";
import Alerts from "./pages/Alerts";
import Dashboard from "./pages/Dashboard";
import Intelligence from "./pages/Intelligence";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Topology from "./pages/Topology";

const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem("session_token");
  const orgId = localStorage.getItem("org_id");

  return token && orgId ? children : <Navigate to="/login" replace />;
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="agents" element={<Agents />} />
          <Route path="intelligence" element={<Intelligence />} />
          <Route path="topology" element={<Topology />} />
          <Route path="alerts" element={<Alerts />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
