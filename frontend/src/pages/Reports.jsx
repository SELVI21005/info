import { useEffect, useState } from "react";
import { AlertTriangle, Calendar, Download, Eye, FileText, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { downloadReport, getReport, getReports } from "../services/api";

function Reports() {
  const [reports, setReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => { loadReports(); }, []);

  async function loadReports() {
    try { setLoading(true); setError(""); const data = await getReports(); setReports(data.reports || []); }
    catch (requestError) { setError(requestError.message || "Unable to load malware analysis reports."); }
    finally { setLoading(false); }
  }

  async function handleView(reportId) {
    try { setBusy(`view-${reportId}`); setError(""); const data = await getReport(reportId); setSelectedReport(data.report); }
    catch (requestError) { setError(requestError.message || "Unable to load this report."); }
    finally { setBusy(""); }
  }

  async function handleDownload(reportId, format) {
    try { setBusy(`${format}-${reportId}`); setError(""); await downloadReport(reportId, format); }
    catch (requestError) { setError(requestError.message || `Unable to download the ${format} report.`); }
    finally { setBusy(""); }
  }

  function classificationIcon(classification) {
    if (classification === "Malware") return <ShieldAlert size={20} />;
    if (classification === "Suspicious") return <AlertTriangle size={20} />;
    return <ShieldCheck size={20} />;
  }

  function reportActions(report) {
    return <div className="report-actions"><button className="refresh-button" onClick={() => handleView(report.id)} disabled={busy === `view-${report.id}`}><Eye size={15} />{busy === `view-${report.id}` ? "Loading..." : "View Report"}</button><button className="refresh-button" onClick={() => handleDownload(report.id, "pdf")} disabled={busy === `pdf-${report.id}`}><Download size={15} />{busy === `pdf-${report.id}` ? "Preparing..." : "Download PDF"}</button><button className="refresh-button" onClick={() => handleDownload(report.id, "excel")} disabled={busy === `excel-${report.id}`}><Download size={15} />{busy === `excel-${report.id}` ? "Preparing..." : "Download Excel"}</button></div>;
  }

  return <div className="reports-page"><div className="page-header"><div><h1>Malware Analysis Reports</h1><p>Review and download reports generated from real file analysis results.</p></div><button className="refresh-button" onClick={loadReports} disabled={loading}><RefreshCw size={17} /> Refresh</button></div>{error && <div className="error-banner">{error}</div>}<div className="reports-card"><div className="section-header"><div><h2>Generated Reports</h2><p>{reports.length} malware analysis report{reports.length !== 1 ? "s" : ""}</p></div></div>{loading ? <div className="loading">Loading reports...</div> : reports.length === 0 ? <div className="empty-state"><FileText size={40} /><h3>No reports available</h3><p>Reports will be generated automatically after file analysis.</p></div> : <div className="reports-list">{reports.map((report) => { const yara = report.static_analysis?.yara_analysis; return <div className="report-item" key={report.id}><div className="report-icon"><FileText size={24} /></div><div className="report-content"><div className="report-title-row"><div><h3>{report.filename}</h3><span className="report-type">{report.report_type || "Malware Analysis Report"}</span></div><span className="classification-badge">{classificationIcon(report.classification)}{report.classification || "Unknown"}</span></div><div className="report-details"><div><span>Risk Score</span><strong>{report.risk_score ?? 0}/100</strong></div><div><span>Risk Level</span><strong>{report.risk_level || "Unknown"}</strong></div><div><span>Generated</span><strong><Calendar size={15} />{report.generated_at ? new Date(report.generated_at).toLocaleString() : "N/A"}</strong></div></div>{reportActions(report)}{report.ml_analysis && <div className="report-section"><h4>Machine Learning Analysis</h4><p>Status: <strong>{report.ml_analysis.status}</strong></p><p>Classification: <strong>{report.ml_analysis.classification}</strong></p><p>Confidence: <strong>{report.ml_analysis.confidence}%</strong></p></div>}{report.static_analysis && <div className="report-section"><h4>Static Analysis Summary</h4><p>Suspicious keywords: <strong>{report.static_analysis.suspicious_keywords?.length || 0}</strong></p><p>URLs detected: <strong>{report.static_analysis.urls?.length || 0}</strong></p><p>IP addresses detected: <strong>{report.static_analysis.ips?.length || 0}</strong></p><p>PE file: <strong>{report.static_analysis.pe_analysis?.is_pe ? "Yes" : "No"}</strong></p></div>}{yara && <div className="report-section"><h4>YARA Analysis</h4><p>Status: <strong>{yara.available ? "Available" : "Unavailable"}</strong></p><p>Rules matched: <strong>{yara.match_count || 0}</strong></p><p>Matched rules: <strong>{yara.matches?.map((match) => match.rule).join(", ") || "None"}</strong></p></div>}{selectedReport?.id === report.id && <div className="report-section report-expanded"><h4>Report Details</h4><p>Report ID: <strong>{selectedReport.id}</strong></p><p>SHA-256: <strong className="hash">{selectedReport.sha256 || selectedReport.static_analysis?.sha256 || "N/A"}</strong></p><p>Alert generated: <strong>{selectedReport.alert_status?.generated ? "Yes" : "No"}</strong></p><p>Risk explanation: <strong>{(selectedReport.risk_explanation || []).join(" ") || "N/A"}</strong></p></div>}</div></div>; })}</div>}</div></div>;
}

export default Reports;
