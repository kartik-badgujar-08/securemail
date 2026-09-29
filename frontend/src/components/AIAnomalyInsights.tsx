import React from "react";
import {
  BrainCircuit,
  Sparkles,
  ShieldCheck,
  AlertOctagon,
  Layers,
  ArrowRight,
} from "lucide-react";
import type { AIInsights, StreamAnomaly } from "../services/api";

interface AIAnomalyInsightsProps {
  insights: AIInsights | null;
  anomalies: StreamAnomaly[];
  isLoading?: boolean;
  onSelectStream?: (streamIndex: number) => void;
}

export const AIAnomalyInsights: React.FC<AIAnomalyInsightsProps> = ({
  insights,
  anomalies,
  isLoading = false,
  onSelectStream,
}) => {
  if (isLoading) {
    return (
      <div className="card" style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
        Running unsupervised Isolation Forest anomaly detection across extracted session telemetry...
      </div>
    );
  }

  if (!insights) {
    return null;
  }

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "BASELINE_CONFORMANT":
        return <span className="badge badge-success">Baseline Conformant (Normal)</span>;
      case "MODERATE_DEVIATION":
        return <span className="badge badge-warning">Moderate Anomaly Deviation</span>;
      case "HIGH_RISK_ANOMALIES":
        return <span className="badge badge-danger">High Risk Anomalies Flagged</span>;
      default:
        return <span className="badge badge-neutral">{verdict}</span>;
    }
  };

  const getMeterColor = (score: number) => {
    if (score <= 25) return "#059669";
    if (score <= 50) return "#d97706";
    if (score <= 75) return "#ea580c";
    return "#dc2626";
  };

  const anomalyPct =
    insights.total_sessions > 0
      ? Math.round((insights.anomalous_sessions_count / insights.total_sessions) * 100)
      : 0;

  return (
    <div className="ai-insights-container">
      {/* Executive AI / Isolation Forest Card */}
      <div className="ai-header-card">
        <div className="ai-header-top">
          <div className="ai-title-wrap">
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: "var(--radius-md)",
                backgroundColor: "#f5f3ff",
                color: "#7c3aed",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <BrainCircuit size={22} />
            </div>
            <div>
              <h2 style={{ fontSize: "1.125rem", fontWeight: 700, color: "var(--text-main)", margin: 0 }}>
                AI & Machine Learning Anomaly Detection
              </h2>
              <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", margin: 0 }}>
                Unsupervised Isolation Forest evaluation trained on standard enterprise email TLS traffic
              </p>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <span className="ai-model-tag">
              <Sparkles size={12} />
              Isolation Forest (scikit-learn)
            </span>
            {getVerdictBadge(insights.ai_verdict)}
          </div>
        </div>

        {/* AI Metrics Grid */}
        <div className="ai-metrics-grid">
          <div className="ai-metric-box">
            <span className="ai-metric-label">AI Anomaly Risk Index</span>
            <div style={{ display: "flex", alignItems: "baseline", gap: "0.5rem" }}>
              <span className="ai-metric-val">{insights.ai_risk_score}</span>
              <span style={{ fontSize: "0.8125rem", color: "var(--text-muted)" }}>/ 100</span>
            </div>
            <div className="risk-meter-track" style={{ width: "100%", marginTop: "0.25rem" }}>
              <div
                className="risk-meter-fill"
                style={{
                  width: `${insights.ai_risk_score}%`,
                  backgroundColor: getMeterColor(insights.ai_risk_score),
                }}
              />
            </div>
          </div>

          <div className="ai-metric-box">
            <span className="ai-metric-label">Anomalous Sessions</span>
            <span className="ai-metric-val">
              {insights.anomalous_sessions_count}{" "}
              <span style={{ fontSize: "0.875rem", fontWeight: 500, color: "var(--text-muted)" }}>
                / {insights.total_sessions}
              </span>
            </span>
            <span className="ai-metric-sub">
              {anomalyPct}% of reconstructed email streams deviate from baseline
            </span>
          </div>

          <div className="ai-metric-box">
            <span className="ai-metric-label">Analyzed Vector Dimension</span>
            <span className="ai-metric-val">11 Features</span>
            <span className="ai-metric-sub">
              TLS ordinal, cipher grade, PFS, STARTTLS, ports, cert chain & client suites
            </span>
          </div>
        </div>

        {/* Primary Anomaly Vectors */}
        {insights.primary_anomaly_vectors.length > 0 && (
          <div>
            <span
              style={{
                fontSize: "0.75rem",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                color: "var(--text-muted)",
              }}
            >
              Primary Anomaly Vectors Identified by Model
            </span>
            <div className="vector-tags-container">
              {insights.primary_anomaly_vectors.map((vec, idx) => (
                <span key={idx} className="vector-tag">
                  <AlertOctagon size={13} />
                  {vec}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Anomalous Sessions Breakdown */}
      <div>
        <h3
          style={{
            fontSize: "1rem",
            fontWeight: 600,
            color: "var(--text-main)",
            marginBottom: "0.875rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <Layers size={18} />
          Flagged Anomalous Sessions ({anomalies.length})
        </h3>

        {anomalies.length === 0 ? (
          <div
            className="card"
            style={{
              padding: "3rem 2rem",
              textAlign: "center",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: "0.75rem",
            }}
          >
            <ShieldCheck size={36} style={{ color: "#10b981" }} />
            <h4 style={{ fontSize: "1rem", fontWeight: 600, color: "var(--text-main)", margin: 0 }}>
              Zero Cryptographic Anomalies Detected
            </h4>
            <p style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", maxWidth: "500px", margin: 0 }}>
              The unsupervised Isolation Forest model verified that all email sessions strictly adhere to standard
              enterprise baseline parameters (modern TLS versions, authenticated AEAD ciphers, and ephemeral key exchange).
            </p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {anomalies.map((st) => (
              <div key={st.stream_id} className="stream-anomaly-card">
                <div className="stream-anomaly-header">
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
                    <span className="badge badge-ai-anomaly">
                      <Sparkles size={12} />
                      AI Score: {Math.round(st.anomaly_score)}/100
                    </span>
                    <span className="badge badge-neutral">Stream #{st.stream_index}</span>
                    <span className="badge badge-neutral">{st.protocol}</span>
                    <span style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--text-main)" }}>
                      {st.client_ip}:{st.client_port} <ArrowRight size={14} style={{ display: "inline" }} />{" "}
                      {st.server_ip}:{st.server_port}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    {st.tls_version ? (
                      <span className="badge badge-neutral">{st.tls_version}</span>
                    ) : (
                      <span className="badge badge-danger">Unencrypted Plaintext</span>
                    )}
                    {st.cipher_suite && (
                      <span
                        className="badge badge-neutral font-mono"
                        style={{ fontSize: "0.75rem", maxWidth: "240px", overflow: "hidden", textOverflow: "ellipsis" }}
                        title={st.cipher_suite}
                      >
                        {st.cipher_suite}
                      </span>
                    )}
                    {onSelectStream && (
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={() => onSelectStream(st.stream_index)}
                        style={{ fontSize: "0.75rem", padding: "0.2rem 0.5rem" }}
                      >
                        Inspect Stream
                      </button>
                    )}
                  </div>
                </div>

                {/* Explanations */}
                <div>
                  <div
                    style={{
                      fontSize: "0.75rem",
                      fontWeight: 700,
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      color: "var(--text-muted)",
                      marginBottom: "0.35rem",
                    }}
                  >
                    Isolation Forest Anomaly Factors:
                  </div>
                  <ul className="anomaly-reasons-list">
                    {st.anomaly_reasons.map((reason, rIdx) => (
                      <li key={rIdx} className="anomaly-reason-item">
                        <span className="anomaly-reason-dot" />
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
