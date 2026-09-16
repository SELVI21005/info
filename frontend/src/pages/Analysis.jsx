import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FileSearch,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Hash,
  Globe,
  Network,
  Code2,
  FileCode2,
} from "lucide-react";

import { downloadReport, getDetections, getReports } from "../services/api";

function Analysis() {
  const navigate = useNavigate();
  const [detections, setDetections] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reportIds, setReportIds] = useState({});
  const [downloadLoading, setDownloadLoading] = useState("");

  useEffect(() => {
    loadAnalysis();
  }, []);

  async function loadAnalysis() {
    try {
      setLoading(true);
      setError("");

      const data = await getDetections();
      const items = data.detections || [];

      setDetections(items);
      try {
        const reportData = await getReports();
        setReportIds(
          Object.fromEntries(
            (reportData.reports || []).map((report) => [
              report.detection_id,
              report.id,
            ])
          )
        );
      } catch (reportError) {
        setReportIds({});
      }

      if (items.length > 0) {
        setSelected(items[items.length - 1]);
      } else {
        setSelected(null);
      }
    } catch (err) {
      setError("Unable to load analysis data.");
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload(format) {
    const reportId = reportIds[selected?.id];
    if (!reportId) {
      setError("A report is not available for this analysis.");
      return;
    }

    try {
      setDownloadLoading(format);
      setError("");
      await downloadReport(reportId, format);
    } catch (downloadError) {
      setError(downloadError.message || `Unable to download the ${format} report.`);
    } finally {
      setDownloadLoading("");
    }
  }

  function classificationIcon(classification) {
    if (classification === "Malware") {
      return <ShieldAlert size={22} />;
    }

    if (classification === "Suspicious") {
      return <AlertTriangle size={22} />;
    }

    return <ShieldCheck size={22} />;
  }

  if (loading) {
    return (
      <div className="analysis-page">
        <div className="loading">
          Loading analysis...
        </div>
      </div>
    );
  }

  return (
    <div className="analysis-page">
      <div className="page-header">
        <div>
          <h1>File Analysis</h1>
          <p>
            Detailed static and machine-learning analysis results.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadAnalysis}
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

      {detections.length === 0 ? (
        <div className="empty-state">
          <FileSearch size={42} />

          <h3>No analysis available</h3>

          <p>
            Upload and analyze a file first to view detailed
            analysis results.
          </p>
        </div>
      ) : (
        <>
          <div className="analysis-selector">
            <label>Select analyzed file</label>

            <select
              value={selected?.id || ""}
              onChange={(event) => {
                const item = detections.find(
                  (detection) =>
                    detection.id === event.target.value
                );

                setSelected(item);
              }}
            >
              {detections.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.filename}
                </option>
              ))}
            </select>
          </div>

          {selected && (
            <>
              <div className="analysis-overview">
                <div className="overview-main">
                  <div className="analysis-file-icon">
                    <FileSearch size={28} />
                  </div>

                  <div>
                    <h2>{selected.filename}</h2>

                    <p>
                      Analyzed{" "}
                      {selected.timestamp
                        ? new Date(
                            selected.timestamp
                          ).toLocaleString()
                        : "N/A"}
                    </p>
                  </div>
                </div>

                <div className="classification-badge">
                  {classificationIcon(
                    selected.classification
                  )}

                  {selected.classification}
                </div>
              </div>

              {reportIds[selected.id] && (
                <div className="report-actions analysis-report-actions">
                  <button className="refresh-button" onClick={() => navigate("/reports")}>
                    View Report
                  </button>
                  <button className="refresh-button" onClick={() => handleDownload("pdf")} disabled={Boolean(downloadLoading)}>
                    {downloadLoading === "pdf" ? "Preparing..." : "Download PDF"}
                  </button>
                  <button className="refresh-button" onClick={() => handleDownload("excel")} disabled={Boolean(downloadLoading)}>
                    {downloadLoading === "excel" ? "Preparing..." : "Download Excel"}
                  </button>
                </div>
              )}

              <div className="analysis-stats">
                <div className="analysis-stat">
                  <span>Risk Score</span>
                  <strong>
                    {selected.risk_score}/100
                  </strong>
                </div>

                <div className="analysis-stat">
                  <span>Risk Level</span>
                  <strong>
                    {selected.risk_level}
                  </strong>
                </div>

                <div className="analysis-stat">
                  <span>File Size</span>
                  <strong>
                    {(
                      selected.file_size / 1024
                    ).toFixed(2)} KB
                  </strong>
                </div>

                <div className="analysis-stat">
                  <span>Strings</span>
                  <strong>
                    {selected.static_analysis
                      ?.strings_count || 0}
                  </strong>
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>File Identification</h2>
                    <p>
                      Cryptographic identifiers for the
                      analyzed file.
                    </p>
                  </div>
                </div>

                <div className="indicator-grid">
                  <div className="indicator-card">
                    <Hash size={20} />

                    <div>
                      <span>SHA-256</span>
                      <strong className="hash">
                        {selected.sha256}
                      </strong>
                    </div>
                  </div>

                  <div className="indicator-card">
                    <Hash size={20} />

                    <div>
                      <span>MD5</span>
                      <strong className="hash">
                        {selected.static_analysis?.md5 ||
                          "N/A"}
                      </strong>
                    </div>
                  </div>
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>YARA Analysis</h2>
                    <p>Rule-based static indicators from the ThreatLens rule set.</p>
                  </div>
                </div>

                <div className="ml-result-card">
                  <div>
                    <span>Status</span>
                    <strong>{selected.static_analysis?.yara_analysis?.available ? "Available" : "Unavailable"}</strong>
                  </div>
                  <div>
                    <span>Rules Matched</span>
                    <strong>{selected.static_analysis?.yara_analysis?.match_count || 0}</strong>
                  </div>
                  <div>
                    <span>Matched Rules</span>
                    <strong>{selected.static_analysis?.yara_analysis?.matches?.map((match) => match.rule).join(", ") || "None"}</strong>
                  </div>
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>Threat Indicators</h2>
                    <p>
                      Suspicious artifacts discovered during
                      static inspection.
                    </p>
                  </div>
                </div>

                <div className="indicator-grid">
                  <div className="indicator-card">
                    <Code2 size={20} />

                    <div>
                      <span>
                        Suspicious Keywords
                      </span>

                      <strong>
                        {selected.static_analysis
                          ?.suspicious_keywords
                          ?.length || 0}
                      </strong>
                    </div>
                  </div>

                  <div className="indicator-card">
                    <Globe size={20} />

                    <div>
                      <span>URLs Detected</span>

                      <strong>
                        {selected.static_analysis?.urls
                          ?.length || 0}
                      </strong>
                    </div>
                  </div>

                  <div className="indicator-card">
                    <Network size={20} />

                    <div>
                      <span>IP Addresses</span>

                      <strong>
                        {selected.static_analysis?.ips
                          ?.length || 0}
                      </strong>
                    </div>
                  </div>

                  <div className="indicator-card">
                    <FileCode2 size={20} />

                    <div>
                      <span>PE File</span>

                      <strong>
                        {selected.static_analysis
                          ?.pe_analysis?.is_pe
                          ? "Yes"
                          : "No"}
                      </strong>
                    </div>
                  </div>
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>Suspicious Keywords</h2>
                    <p>
                      Keywords associated with potentially
                      suspicious behavior.
                    </p>
                  </div>
                </div>

                <div className="tag-container">
                  {selected.static_analysis
                    ?.suspicious_keywords?.length > 0 ? (
                    selected.static_analysis.suspicious_keywords.map(
                      (keyword) => (
                        <span
                          className="threat-tag"
                          key={keyword}
                        >
                          {keyword}
                        </span>
                      )
                    )
                  ) : (
                    <p>No suspicious keywords detected.</p>
                  )}
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>Machine Learning Analysis</h2>
                    <p>
                      Random Forest malware classification
                      result.
                    </p>
                  </div>
                </div>

                <div className="ml-result-card">
                  <div>
                    <span>Status</span>

                    <strong>
                      {selected.ml_analysis?.status ||
                        "Not available"}
                    </strong>
                  </div>

                  <div>
                    <span>Classification</span>

                    <strong>
                      {selected.ml_analysis
                        ?.classification || "Unknown"}
                    </strong>
                  </div>

                  <div>
                    <span>Confidence</span>

                    <strong>
                      {selected.ml_analysis?.confidence ??
                        0}
                      %
                    </strong>
                  </div>
                </div>
              </div>

              <div className="analysis-section">
                <div className="section-header">
                  <div>
                    <h2>PE Analysis</h2>
                    <p>
                      Portable Executable structural
                      information.
                    </p>
                  </div>
                </div>

                <div className="pe-grid">
                  <div>
                    <span>PE Detected</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis?.is_pe
                        ? "Yes"
                        : "No"}
                    </strong>
                  </div>

                  <div>
                    <span>Machine</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis?.machine ||
                        "N/A"}
                    </strong>
                  </div>

                  <div>
                    <span>Sections</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis
                        ?.number_of_sections ??
                        "N/A"}
                    </strong>
                  </div>

                  <div>
                    <span>Entry Point</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis?.entry_point ||
                        "N/A"}
                    </strong>
                  </div>

                  <div>
                    <span>Image Base</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis?.image_base ||
                        "N/A"}
                    </strong>
                  </div>

                  <div>
                    <span>Imports</span>
                    <strong>
                      {selected.static_analysis
                        ?.pe_analysis?.imports
                        ?.length || 0}
                    </strong>
                  </div>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

export default Analysis;