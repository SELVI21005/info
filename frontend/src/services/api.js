const API_BASE_URL = "http://127.0.0.1:8001";
const TOKEN_KEY = "threatlens_token";

async function parseResponse(response, fallbackMessage) {
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.detail || data.message || fallbackMessage);
  }

  return data;
}

function authHeaders() {
  const token = localStorage.getItem(TOKEN_KEY);

  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function signup(name, email, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });

  return parseResponse(response, "Unable to create account");
}

export async function signin(email, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/signin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const data = await parseResponse(response, "Unable to sign in");

  localStorage.setItem(TOKEN_KEY, data.access_token);
  return data;
}

export async function forgotPassword(email) {
  const response = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });

  return parseResponse(response, "Unable to request a password reset");
}

export async function resetPassword(token, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, password }),
  });

  return parseResponse(response, "Unable to reset your password");
}

export async function getCurrentUser() {
  const token = localStorage.getItem(TOKEN_KEY);

  if (!token) {
    throw new Error("No active session");
  }

  const response = await fetch(`${API_BASE_URL}/api/auth/me`, {
    headers: authHeaders(),
  });

  try {
    return await parseResponse(response, "Your session has expired");
  } catch (error) {
    if (response.status === 401) {
      logout();
    }
    throw error;
  }
}

export function logout() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function getDashboard() {
  const response = await fetch(`${API_BASE_URL}/api/dashboard`, {
    headers: authHeaders(),
  });

  return parseResponse(response, "Failed to load dashboard");
}

export async function getDetections() {
  const response = await fetch(`${API_BASE_URL}/api/detections`, {
    headers: authHeaders(),
  });

  return parseResponse(response, "Failed to load detections");
}

export async function getAlerts() {
  const response = await fetch(`${API_BASE_URL}/api/alerts`, {
    headers: authHeaders(),
  });

  return parseResponse(response, "Failed to load alerts");
}

export async function getReports() {
  const response = await fetch(`${API_BASE_URL}/api/reports`, {
    headers: authHeaders(),
  });

  return parseResponse(response, "Failed to load reports");
}

export async function getReport(reportId) {
  const response = await fetch(`${API_BASE_URL}/api/reports/${reportId}`, {
    headers: authHeaders(),
  });

  return parseResponse(response, "Failed to load report");
}

export async function downloadReport(reportId, format) {
  const response = await fetch(
    `${API_BASE_URL}/api/reports/${reportId}/${format}`,
    { headers: authHeaders() }
  );

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `Failed to download ${format} report`);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = `ThreatLens_Report_${reportId}.${format === "excel" ? "xlsx" : "pdf"}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

export async function analyzeFile(file) {
  const formData = new FormData();

  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: "POST",
    headers: authHeaders(),
    body: formData,
  });

  return parseResponse(response, "File analysis failed");
}