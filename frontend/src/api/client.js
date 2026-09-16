import axios from "axios";

// =========================
// BASE API
// =========================
const API = axios.create({
  baseURL: "http://localhost:5000",
  timeout: 10000
});

// =========================
// AUTO ATTACH AUTH HEADERS
// =========================
API.interceptors.request.use((config) => {

  const apiKey = localStorage.getItem("api_key");
  const orgId = localStorage.getItem("org_id");

  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  }

  if (orgId) {
    config.headers["X-ORG-ID"] = orgId;
  }

  return config;
});

// =========================
// GLOBAL ERROR HANDLING
// =========================
API.interceptors.response.use(
  (res) => res,
  (err) => {
    console.error("API Error:", err?.response?.data || err.message);
    return Promise.reject(err);
  }
);

export { API };
export default API;