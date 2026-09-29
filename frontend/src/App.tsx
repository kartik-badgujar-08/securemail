import React, { useState, useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  FileText,
  Mail,
  ShieldAlert,
  Layers,
  BrainCircuit,
  FileDown,
  Printer,
  Code2,
} from "lucide-react";
import { UploadDropzone } from "./components/UploadDropzone";
import { StreamTable } from "./components/StreamTable";
import { PacketDrawer } from "./components/PacketDrawer";
import { VulnerabilityFindings } from "./components/VulnerabilityFindings";
import { AIAnomalyInsights } from "./components/AIAnomalyInsights";
import { api } from "./services/api";
import type {
  JobStatusResponse,
  TCPStream,
  UploadResponse,
  VulnerabilityFinding,
  RiskSummary,
  StreamAnomaly,
  AIInsights,
} from "./services/api";

export const App: React.FC = () => {
  const [activeJob, setActiveJob] = useState<JobStatusResponse | null>(null);
  const [streams, setStreams] = useState<TCPStream[]>([]);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [aiInsights, setAiInsights] = useState<AIInsights | null>(null);
  const [anomalies, setAnomalies] = useState<StreamAnomaly[]>([]);
  const [selectedStream, setSelectedStream] = useState<TCPStream | null>(null);
  const [systemEngine, setSystemEngine] = useState<string>("Detecting...");
  const [uploadNotice, setUploadNotice] = useState<string | null>(null);
  const [loadingStreams, setLoadingStreams] = useState<boolean>(false);
  const [loadingFindings, setLoadingFindings] = useState<boolean>(false);
  const [loadingAI, setLoadingAI] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<"STREAMS" | "FINDINGS" | "AI_INSIGHTS">("STREAMS");

  // Check health and engine status on mount
  useEffect(() => {
    api
      .checkHealth()
      .then((data) => {
        setSystemEngine(
          data.tshark_installed
            ? "TShark Engine (Active)"
            : "Scapy Engine (Fallback Active)"
        );
      })
      .catch(() => {
        setSystemEngine("Backend Offline");
      });
  }, []);

  // Poll job status until COMPLETED or FAILED
  useEffect(() => {
    if (!activeJob) return;
    if (activeJob.status === "COMPLETED" || activeJob.status === "FAILED") return;

    const interval = setInterval(async () => {
      try {
        const updated = await api.getJobStatus(activeJob.job_id);
        setActiveJob(updated);
        if (updated.status === "COMPLETED") {
          loadJobData(updated.job_id);
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeJob]);

  const loadJobData = async (jobId: string) => {
    setLoadingStreams(true);
    setLoadingFindings(true);
    setLoadingAI(true);
    try {
      const [streamsData, findingsData, summaryData, insightsData, anomaliesData] = await Promise.all([
        api.getJobStreams(jobId),
        api.getJobFindings(jobId),
        api.getJobRiskSummary(jobId),
        api.getJobAIInsights(jobId),
        api.getJobAnomalies(jobId),
      ]);
      setStreams(streamsData);
      setFindings(findingsData);
      setRiskSummary(summaryData);
      setAiInsights(insightsData);
      setAnomalies(anomaliesData);
    } catch (err) {
      console.error("Error loading job data:", err);
    } finally {
      setLoadingStreams(false);
      setLoadingFindings(false);
      setLoadingAI(false);
    }
  };

  const handleUploadSuccess = (response: UploadResponse) => {
    setUploadNotice(response.message);
    setActiveJob({
      job_id: response.job_id,
      filename: response.filename,
      file_size_bytes: response.file_size_bytes,
      sha256_hash: response.sha256_hash,
      status: "QUEUED",
      is_duplicate: response.is_duplicate,
      total_packets: 0,
      total_sessions: 0,
      risk_score: 0,
      ml_anomaly_count: 0,
      ml_risk_score: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    setStreams([]);
    setFindings([]);
    setRiskSummary(null);
    setAiInsights(null);
    setAnomalies([]);
  };

  const handleInspectStreamFromAI = (streamIndex: number) => {
    const found = streams.find((s) => s.stream_index === streamIndex);
    if (found) {
      setSelectedStream(found);
    }
  };

  // Metrics computation
  const totalSessions = streams.length;
  const smtpCount = streams.filter((s) => s.protocol === "SMTP").length;
  const imapPopCount = streams.filter((s) => s.protocol === "IMAP" || s.protocol === "POP3").length;
  const starttlsCount = streams.filter((s) => s.has_starttls).length;
  const cleartextCount = streams.filter((s) => !s.is_tls_encrypted).length;

  return (
    <div className="app-container">
      {/* Top Enterprise Navigation */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-icon-box">
            <Mail size={22} />
          </div>
          <div>
            <h1 className="brand-title">MailSec TLS</h1>
            <p className="brand-subtitle">Email Protocol Security & TLS Handshake Auditor</p>
          </div>
        </div>

        <div className="header-status">
          <div className="engine-indicator">
            <span
              className="status-dot"
              style={{
                backgroundColor: systemEngine.includes("Offline")
                  ? "#ef4444"
                  : systemEngine.includes("TShark")
                  ? "#10b981"
                  : "#f59e0b",
              }}
            />
            <span>{systemEngine}</span>
          </div>
        </div>
      </header>

      {/* Main Content View */}
      <main className="main-content">
        {/* Upload Alert Notice (e.g. Option B Duplicate Warning or Success) */}
        {uploadNotice && (
          <div
            className={`alert ${
              uploadNotice.includes("Notice") || uploadNotice.includes("duplicate")
                ? "alert-warning"
                : "alert-success"
            }`}
            role="alert"
          >
            {uploadNotice.includes("Notice") ? (
              <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            ) : (
              <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            )}
            <div style={{ flex: 1 }}>{uploadNotice}</div>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => setUploadNotice(null)}
              style={{ padding: "0.15rem 0.5rem" }}
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Capture Overview & Job Status Banner (if a job is active) */}
        {activeJob && (
          <div className="card" style={{ marginBottom: "1.5rem" }}>
            <div className="card-header">
              <span className="card-title">
                <FileText size={18} />
                Active Capture: <strong>{activeJob.filename}</strong>
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <span
                  className={`badge ${
                    activeJob.status === "COMPLETED"
                      ? "badge-success"
                      : activeJob.status === "FAILED"
                      ? "badge-danger"
                      : "badge-warning"
                  }`}
                >
                  {activeJob.status}
                </span>
                {activeJob.parser_engine_used && (
                  <span className="badge badge-neutral">
                    Engine: {activeJob.parser_engine_used}
                  </span>
                )}
                {activeJob.is_duplicate && (
                  <span className="badge badge-warning">Duplicate Capture (Option B)</span>
                )}
                {activeJob.status === "COMPLETED" && (
                  <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                    <a
                      href={api.getReportPdfUrl(activeJob.job_id)}
                      download={`MailSec_Audit_${activeJob.filename.replace(/\.[^/.]+$/, "")}.pdf`}
                      className="btn btn-primary btn-sm"
                      style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "0.35rem" }}
                      title="Download Native PDF Executive Audit Report"
                    >
                      <FileDown size={13} />
                      Export PDF
                    </a>
                    <a
                      href={api.getReportHtmlUrl(activeJob.job_id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-outline btn-sm"
                      style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "0.35rem" }}
                      title="Open Printable HTML Executive Report"
                    >
                      <Printer size={13} />
                      HTML Report
                    </a>
                    <a
                      href={api.getReportJsonUrl(activeJob.job_id)}
                      download={`MailSec_Audit_${activeJob.filename.replace(/\.[^/.]+$/, "")}.json`}
                      className="btn btn-outline btn-sm"
                      style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: "0.35rem" }}
                      title="Download SIEM/SOAR Structured JSON Report"
                    >
                      <Code2 size={13} />
                      JSON
                    </a>
                  </div>
                )}
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => activeJob && loadJobData(activeJob.job_id)}
                  title="Reload analysis"
                >
                  <RefreshCw size={13} />
                  Refresh
                </button>
              </div>
            </div>
            <div className="card-body" style={{ padding: "0.875rem 1.5rem", fontSize: "0.8125rem", color: "var(--text-secondary)" }}>
              <div style={{ display: "flex", gap: "2rem", flexWrap: "wrap", alignItems: "center" }}>
                <div>
                  <strong>Size:</strong> {(activeJob.file_size_bytes / 1024).toFixed(1)} KB
                </div>
                <div>
                  <strong>Packets:</strong> {activeJob.total_packets}
                </div>
                <div>
                  <strong>Sessions:</strong> {activeJob.total_sessions}
                </div>
                <div>
                  <strong>SHA-256:</strong> <span className="font-mono">{activeJob.sha256_hash.slice(0, 16)}...</span>
                </div>
                {riskSummary && (
                  <div>
                    <strong>Risk Score:</strong>{" "}
                    <span style={{ fontWeight: 700, color: riskSummary.risk_score > 35 ? "#dc2626" : "#059669" }}>
                      {riskSummary.risk_score}/100 ({riskSummary.risk_grade})
                    </span>
                  </div>
                )}
                {aiInsights && (
                  <div>
                    <strong>AI Anomaly Index:</strong>{" "}
                    <span
                      style={{
                        fontWeight: 700,
                        color: aiInsights.ai_risk_score > 40 ? "#7c3aed" : "#059669",
                      }}
                    >
                      {aiInsights.ai_risk_score}/100 ({aiInsights.anomalous_sessions_count} anomalous)
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Executive Stats Summary Cards */}
        {streams.length > 0 && (
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Total Sessions</div>
              <div className="stat-value">{totalSessions}</div>
              <div className="stat-sub">Reconstructed TCP Streams</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">SMTP Streams</div>
              <div className="stat-value">{smtpCount}</div>
              <div className="stat-sub">Port 25 / 587 traffic</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">IMAP & POP3 Streams</div>
              <div className="stat-value">{imapPopCount}</div>
              <div className="stat-sub">Port 143, 993, 110, 995</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">STARTTLS Transitions</div>
              <div className="stat-value" style={{ color: "#059669" }}>
                {starttlsCount}
              </div>
              <div className="stat-sub">Plaintext upgraded to TLS</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">Cleartext Insecure</div>
              <div className="stat-value" style={{ color: cleartextCount > 0 ? "#dc2626" : "var(--text-main)" }}>
                {cleartextCount}
              </div>
              <div className="stat-sub">Unencrypted email sessions</div>
            </div>

            <div className="stat-card">
              <div className="stat-label">AI Anomalies</div>
              <div
                className="stat-value"
                style={{ color: anomalies.length > 0 ? "#7c3aed" : "var(--text-main)" }}
              >
                {anomalies.length}
              </div>
              <div className="stat-sub">Isolation Forest detections</div>
            </div>
          </div>
        )}

        {/* Module 1: Upload Zone */}
        <UploadDropzone
          onUploadSuccess={handleUploadSuccess}
          isProcessing={activeJob?.status === "PROCESSING" || activeJob?.status === "QUEUED"}
        />

        {/* View Tabs: Sessions Explorer vs Vulnerabilities vs AI/ML Anomaly Insights */}
        {activeJob && (
          <div className="view-tabs">
            <button
              className={`view-tab-btn ${activeTab === "STREAMS" ? "active" : ""}`}
              onClick={() => setActiveTab("STREAMS")}
            >
              <Layers size={16} />
              <span>Sessions Explorer</span>
              {streams.length > 0 && <span className="tab-badge">{streams.length}</span>}
            </button>
            <button
              className={`view-tab-btn ${activeTab === "FINDINGS" ? "active" : ""}`}
              onClick={() => setActiveTab("FINDINGS")}
            >
              <ShieldAlert
                size={16}
                style={{ color: findings.some((f) => f.severity === "CRITICAL") ? "#dc2626" : undefined }}
              />
              <span>Vulnerabilities & Risk Posture</span>
              {findings.length > 0 && (
                <span
                  className="tab-badge"
                  style={
                    findings.some((f) => f.severity === "CRITICAL")
                      ? { backgroundColor: "#fef2f2", color: "#dc2626" }
                      : undefined
                  }
                >
                  {findings.length}
                </span>
              )}
            </button>
            <button
              className={`view-tab-btn ${activeTab === "AI_INSIGHTS" ? "active" : ""}`}
              onClick={() => setActiveTab("AI_INSIGHTS")}
            >
              <BrainCircuit
                size={16}
                style={{ color: anomalies.length > 0 ? "#7c3aed" : undefined }}
              />
              <span>AI Anomaly Insights</span>
              {anomalies.length > 0 ? (
                <span
                  className="tab-badge"
                  style={{ backgroundColor: "#f5f3ff", color: "#6d28d9" }}
                >
                  {anomalies.length}
                </span>
              ) : (
                <span className="tab-badge">Normal</span>
              )}
            </button>
          </div>
        )}

        {/* Tab 1: Module 2 & 3 Reconstructed Streams Table */}
        {activeJob && activeTab === "STREAMS" && (
          <StreamTable
            streams={streams}
            onSelectStream={(st) => setSelectedStream(st)}
            isLoading={loadingStreams || activeJob.status === "PROCESSING" || activeJob.status === "QUEUED"}
          />
        )}

        {/* Tab 2: Module 4 Vulnerability Findings & Risk Score */}
        {activeJob && activeTab === "FINDINGS" && (
          <VulnerabilityFindings
            findings={findings}
            riskSummary={riskSummary}
            isLoading={loadingFindings || activeJob.status === "PROCESSING" || activeJob.status === "QUEUED"}
          />
        )}

        {/* Tab 3: Module 5 AI / ML Anomaly Insights */}
        {activeJob && activeTab === "AI_INSIGHTS" && (
          <AIAnomalyInsights
            insights={aiInsights}
            anomalies={anomalies}
            isLoading={loadingAI || activeJob.status === "PROCESSING" || activeJob.status === "QUEUED"}
            onSelectStream={handleInspectStreamFromAI}
          />
        )}

        {/* Deep Packet Inspector Drawer */}
        {activeJob && (
          <PacketDrawer
            stream={selectedStream}
            jobId={activeJob.job_id}
            onClose={() => setSelectedStream(null)}
          />
        )}
      </main>
    </div>
  );
};

export default App;
