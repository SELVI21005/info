import { useEffect, useState } from "react";
import {
  FileSearch,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";

import { getDetections } from "../services/api";

function History() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadDetections();
  }, []);

  async function loadDetections() {
    try {
      setLoading(true);
      setError("");

      const data = await getDetections();
      setDetections(data.detections || []);
    } catch (err) {
      setError("Unable to load detection history.");
    } finally {
      setLoading(false);
    }
  }

  function getIcon(classification) {
    if (classification === "Malware") {
      return <ShieldAlert size={20} />;
    }

    if (classification === "Suspicious") {
      return <AlertTriangle size={20} />;
    }

    return <ShieldCheck size={20} />;
  }

  return (
    <div className="history-page">
      <div className="page-header">
        <div>
          <h1>Detection History</h1>
          <p>
            Review previously analyzed files and their security results.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadDetections}
          disabled={loading}
        >
          <RefreshCw size={17} />
          Refresh
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="history-card">
        <div className="section-header">
          <div>
            <h2>Analyzed Files</h2>
            <p>{detections.length} detection records</p>
          </div>
        </div>

        {loading ? (
          <div className="loading">Loading detection history...</div>
        ) : detections.length === 0 ? (
          <div className="empty-state">
            <FileSearch size={40} />
            <h3>No files analyzed yet</h3>
            <p>
              Upload a file from the Analyze File page to create a detection
              record.
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="detection-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Classification</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>SHA-256</th>
                  <th>Analyzed At</th>
                </tr>
              </thead>

              <tbody>
                {detections.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <div className="file-name">
                        <FileSearch size={18} />
                        <span>{item.filename}</span>
                      </div>
                    </td>

                    <td>
                      <span className="classification-badge">
                        {getIcon(item.classification)}
                        {item.classification}
                      </span>
                    </td>

                    <td>
                      <strong>{item.risk_score}/100</strong>
                    </td>

                    <td>
                      <span className="risk-badge">
                        {item.risk_level}
                      </span>
                    </td>

                    <td>
                      <span className="hash">
                        {item.sha256}
                      </span>
                    </td>

                    <td>
                      {item.timestamp
                        ? new Date(item.timestamp).toLocaleString()
                        : "N/A"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default History;