import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  FileSearch,
  AlertTriangle,
  Activity,
} from "lucide-react";

import { getDashboard } from "../services/api";

const EMPTY_DASHBOARD = {
  total_files: 0,
  malware: 0,
  suspicious: 0,
  benign: 0,
  high_risk: 0,
  medium_risk: 0,
  low_risk: 0,
  total_alerts: 0,
};

function normalizeDashboard(payload) {
  const dashboard =
    payload && typeof payload === "object" && payload.dashboard
      ? payload.dashboard
      : {};

  return {
    ...EMPTY_DASHBOARD,
    ...(typeof dashboard === "object" ? dashboard : {}),
  };
}

function Dashboard() {
  const [dashboard, setDashboard] = useState(EMPTY_DASHBOARD);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      setError("");

      const data = await getDashboard();
      setDashboard(normalizeDashboard(data));
    } catch (err) {
      setDashboard(EMPTY_DASHBOARD);
      setError(
        "Backend is not connected. Start the FastAPI server to load live data."
      );
    } finally {
      setLoading(false);
    }
  }

  const stats = dashboard ?? EMPTY_DASHBOARD;

  const cards = [
    {
      title: "Files Analyzed",
      value: stats.total_files ?? 0,
      icon: FileSearch,
    },
    {
      title: "Malware Detected",
      value: stats.malware ?? 0,
      icon: ShieldAlert,
    },
    {
      title: "Suspicious",
      value: stats.suspicious ?? 0,
      icon: AlertTriangle,
    },
    {
      title: "Likely Benign",
      value: stats.benign ?? 0,
      icon: ShieldCheck,
    },
    {
      title: "High Risk",
      value: stats.high_risk ?? 0,
      icon: Activity,
    },
    {
      title: "Active Alerts",
      value: stats.total_alerts ?? 0,
      icon: ShieldAlert,
    },
  ];

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <div>
          <h1>Threat Dashboard</h1>
          <p>
            Monitor malware detection activity and security events.
          </p>
        </div>

        <button onClick={loadDashboard} className="refresh-button">
          Refresh
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={loadDashboard} className="refresh-button">
            Retry
          </button>
        </div>
      )}

      {loading && (
        <div className="loading">
          Loading...
        </div>
      )}

      <div className="stats-grid">
        {cards.map((card) => {
          const Icon = card.icon;

          return (
            <div className="stat-card" key={card.title}>
              <div className="stat-icon">
                <Icon size={22} />
              </div>

              <div>
                <p>{card.title}</p>
                <h2>{card.value ?? 0}</h2>
              </div>
            </div>
          );
        })}
      </div>

      <div className="dashboard-section">
        <div className="section-header">
          <div>
            <h2>Threat Monitoring</h2>
            <p>
              Real-time statistics from analyzed files.
            </p>
          </div>
        </div>

        <div className="monitoring-card">
          <div>
            <span>Total detections</span>
            <strong>{stats.total_files ?? 0}</strong>
          </div>

          <div>
            <span>High-risk detections</span>
            <strong>{stats.high_risk ?? 0}</strong>
          </div>

          <div>
            <span>Alerts generated</span>
            <strong>{stats.total_alerts ?? 0}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;