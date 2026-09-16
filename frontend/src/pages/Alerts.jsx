import { useEffect, useState } from "react";
import {
  ShieldAlert,
  RefreshCw,
  AlertTriangle,
  Clock,
} from "lucide-react";

import { getAlerts } from "../services/api";

function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadAlerts();
  }, []);

  async function loadAlerts() {
    try {
      setLoading(true);
      setError("");

      const data = await getAlerts();
      setAlerts(data.alerts || []);
    } catch (err) {
      setError("Unable to load security alerts.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="alerts-page">
      <div className="page-header">
        <div>
          <h1>Security Alerts</h1>
          <p>
            Monitor high-risk files detected by ThreatLens AI.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadAlerts}
          disabled={loading}
        >
          <RefreshCw size={17} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <div className="alerts-summary">
        <div className="stat-card">
          <div className="stat-icon">
            <ShieldAlert size={22} />
          </div>

          <div>
            <p>Total Alerts</p>
            <h2>{alerts.length}</h2>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <AlertTriangle size={22} />
          </div>

          <div>
            <p>High Risk</p>
            <h2>
              {
                alerts.filter(
                  (alert) => alert.risk_level === "High"
                ).length
              }
            </h2>
          </div>
        </div>
      </div>

      <div className="alerts-card">
        <div className="section-header">
          <div>
            <h2>Threat Alerts</h2>
            <p>
              Alerts generated when the risk score reaches the
              configured threshold.
            </p>
          </div>
        </div>

        {loading ? (
          <div className="loading">
            Loading security alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <ShieldAlert size={40} />

            <h3>No active alerts</h3>

            <p>
              High-risk detections will appear here automatically.
            </p>
          </div>
        ) : (
          <div className="alerts-list">
            {alerts.map((alert) => (
              <div className="alert-item" key={alert.id}>
                <div className="alert-icon">
                  <ShieldAlert size={22} />
                </div>

                <div className="alert-content">
                  <div className="alert-title-row">
                    <h3>{alert.message}</h3>

                    <span className="risk-badge">
                      {alert.risk_level}
                    </span>
                  </div>

                  <p>
                    File: <strong>{alert.filename}</strong>
                  </p>

                  <div className="alert-meta">
                    <span>
                      Risk Score:{" "}
                      <strong>{alert.risk_score}/100</strong>
                    </span>

                    <span>
                      <Clock size={15} />

                      {alert.timestamp
                        ? new Date(
                            alert.timestamp
                          ).toLocaleString()
                        : "N/A"}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Alerts;