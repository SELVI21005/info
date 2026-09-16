import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { UploadCloud, FileSearch, CheckCircle, AlertCircle } from "lucide-react";

import { analyzeFile, downloadReport } from "../services/api";

function Upload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [downloadLoading, setDownloadLoading] = useState("");

  function handleFileChange(event) {
    const selectedFile = event.target.files[0];

    if (!selectedFile) {
      return;
    }

    setFile(selectedFile);
    setResult(null);
    setError("");
  }

  async function handleDownload(format) {
    if (!result?.report_id) {
      setError("This analysis does not have a report available yet.");
      return;
    }

    try {
      setDownloadLoading(format);
      setError("");
      await downloadReport(result.report_id, format);
    } catch (downloadError) {
      setError(downloadError.message || `Unable to download the ${format} report.`);
    } finally {
      setDownloadLoading("");
    }
  }

  async function handleAnalyze() {
    if (!file) {
      setError("Please select a file first.");
      return;
    }

    try {
      setLoading(true);
      setError("");
      setResult(null);

      const data = await analyzeFile(file);

      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const detection = result?.detection;

  return (
    <div className="upload-page">
      <div className="page-header">
        <div>
          <h1>File Analysis</h1>
          <p>
            Upload a file for static malware analysis.
          </p>
        </div>
      </div>

      <div className="upload-card">
        <div className="upload-icon">
          <UploadCloud size={36} />
        </div>

        <h2>Select a file</h2>

        <p>
          ThreatLens AI will inspect the file without executing it.
        </p>

        <label className="file-input">
          Choose File
          <input
            type="file"
            onChange={handleFileChange}
          />
        </label>

        {file && (
          <div className="selected-file">
            <FileSearch size={20} />

            <div>
              <strong>{file.name}</strong>
              <span>
                {(file.size / 1024).toFixed(2)} KB
              </span>
            </div>
          </div>
        )}

        <button
          className="analyze-button"
          onClick={handleAnalyze}
          disabled={!file || loading}
        >
          {loading ? "Analyzing..." : "Analyze File"}
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <AlertCircle size={20} />
          {error}
        </div>
      )}

      {detection && (
        <div className="result-card">
          <div className="result-header">
            <div>
              <h2>Analysis Result</h2>
              <p>{detection.filename}</p>
            </div>

            <CheckCircle size={28} />
          </div>

          <div className="result-grid">
            <div>
              <span>Classification</span>
              <strong>
                {detection.classification}
              </strong>
            </div>

            <div>
              <span>Risk Score</span>
              <strong>
                {detection.risk_score}/100
              </strong>
            </div>

            <div>
              <span>Risk Level</span>
              <strong>
                {detection.risk_level}
              </strong>
            </div>

            <div>
              <span>SHA-256</span>
              <strong className="hash">
                {detection.sha256}
              </strong>
            </div>
          </div>

          <div className="analysis-details">
            <h3>Static Indicators</h3>

            <p>
              Suspicious keywords:{" "}
              {detection.static_analysis
                ?.suspicious_keywords?.length || 0}
            </p>

            <p>
              URLs detected:{" "}
              {detection.static_analysis
                ?.urls?.length || 0}
            </p>

            <p>
              IP addresses detected:{" "}
              {detection.static_analysis
                ?.ips?.length || 0}
            </p>

            <p>
              PE file:{" "}
              {detection.static_analysis
                ?.pe_analysis?.is_pe
                ? "Yes"
                : "No"}
            </p>
          </div>

          <div className="ml-status">
            <h3>Machine Learning Analysis</h3>

            <p>
              {detection.ml_analysis?.status ===
              "waiting_for_model"
                ? "Random Forest model is waiting for training. It will be connected after the dataset is prepared."
                : `Classification: ${detection.ml_analysis?.classification}`}
            </p>
          </div>

          {result.report_id && (
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
        </div>
      )}
    </div>
  );
}

export default Upload;