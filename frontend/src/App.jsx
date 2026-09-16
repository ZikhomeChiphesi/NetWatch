import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import MainLayout from "./layout/MainLayout";

import Dashboard from "./pages/Dashboard";
import Agents from "./pages/Agents";
import Intelligence from "./pages/Intelligence";
import Topology from "./pages/Topology";

import Login from "./pages/Login";
import Register from "./pages/Register";

// =========================
// PROTECTED ROUTE (SAAS READY)
// =========================
const ProtectedRoute = ({ children }) => {
  const apiKey = localStorage.getItem("api_key");

  return apiKey ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* AUTH ROUTES */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* PROTECTED APP */}
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
        </Route>

      </Routes>
    </BrowserRouter>
  );
}

export default App;