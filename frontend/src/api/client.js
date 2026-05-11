import axios from "axios";

// =========================
// BASE BACKEND CONNECTION
// =========================
const API = axios.create({
  baseURL: "http://localhost:5000", // change to Render URL in production
  timeout: 10000
});

// =========================
// OPTIONAL: REQUEST INTERCEPTOR
// (future: auth tokens, org IDs, etc.)
// =========================
API.interceptors.request.use(
  (config) => {
    // Example for future SaaS auth:
    // config.headers["Authorization"] = "Bearer TOKEN"

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// =========================
// OPTIONAL: RESPONSE HANDLING
// =========================
API.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error("API Error:", error?.response?.data || error.message);
    return Promise.reject(error);
  }
);

export { API };