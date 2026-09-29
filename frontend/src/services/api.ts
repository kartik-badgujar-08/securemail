const API_BASE_URL = import.meta.env.VITE_API_URL || "";

export interface UploadResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  sha256_hash: string;
  status: string;
  is_duplicate: boolean;
  message: string;
}

export interface Certificate {
  id: string;
  job_id: string;
  stream_id?: string;
  fingerprint_sha256: string;
  serial_number?: string;
  subject_cn: string;
  subject_org?: string;
  issuer_cn: string;
  issuer_org?: string;
  is_self_signed: boolean;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  days_until_expiry: number;
  not_valid_before: string;
  not_valid_after: string;
  san_dns_names: string[];
  public_key_algorithm: string;
  public_key_bits: number;
  is_weak_key: boolean;
  signature_algorithm: string;
  signature_hash: string;
  is_weak_hash: boolean;
  chain_position: number;
}

export interface TCPStream {
  id: string;
  stream_index: number;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  protocol: string;
  has_starttls: boolean;
  starttls_packet_index?: number;
  is_tls_encrypted: boolean;
  tls_version?: string;
  cipher_suite?: string;
  has_pfs?: boolean;
  key_exchange?: string;
  sni?: string;
  details?: Record<string, any>;
  anomaly_score?: number;
  is_anomaly?: boolean;
  anomaly_reasons?: string[];
}

export interface TLSHandshakeDetail {
  stream_id: string;
  stream_index: number;
  protocol: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  has_starttls: boolean;
  is_tls_encrypted: boolean;
  tls_version?: string;
  cipher_suite?: string;
  has_pfs: boolean;
  key_exchange?: string;
  sni?: string;
  client_cipher_suites: Array<{
    name: string;
    hex_code: string;
    kx: string;
    bulk: string;
    hash: string;
    pfs: boolean;
    security: "SECURE" | "ACCEPTABLE" | "WEAK" | "INSECURE";
  }>;
  certificates: Certificate[];
}

export interface PacketRecord {
  packet_number: number;
  timestamp: number;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  packet_length: number;
  tcp_flags?: {
    syn?: boolean;
    ack?: boolean;
    fin?: boolean;
    rst?: boolean;
    push?: boolean;
    urg?: boolean;
    raw?: string;
  };
  tls_info?: Record<string, any>;
  smtp_info?: Record<string, any>;
  imap_info?: Record<string, any>;
  pop3_info?: Record<string, any>;
}

export interface VulnerabilityFinding {
  id: string;
  job_id: string;
  stream_id?: string;
  rule_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: "PROTOCOL" | "CIPHER" | "KEY_EXCHANGE" | "CERTIFICATE";
  affected_entity: string;
  description: string;
  remediation: string;
  evidence?: Record<string, any>;
  created_at: string;
}

export interface RiskSummary {
  job_id: string;
  risk_score: number;
  risk_grade: "A+" | "A" | "B" | "C" | "F";
  risk_level: "SECURE" | "LOW RISK" | "MODERATE RISK" | "HIGH RISK" | "CRITICAL RISK";
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface StreamAnomaly {
  stream_id: string;
  stream_index: number;
  protocol: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  is_anomaly: boolean;
  anomaly_score: number;
  anomaly_reasons: string[];
  tls_version?: string;
  cipher_suite?: string;
  has_pfs: boolean;
}

export interface AIInsights {
  job_id: string;
  total_sessions: number;
  anomalous_sessions_count: number;
  ai_risk_score: number;
  ai_verdict: "BASELINE_CONFORMANT" | "MODERATE_DEVIATION" | "HIGH_RISK_ANOMALIES";
  primary_anomaly_vectors: string[];
  anomalous_streams: StreamAnomaly[];
}

export interface JobStatusResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  sha256_hash: string;
  status: "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED";
  parser_engine_used?: string;
  is_duplicate: boolean;
  total_packets: number;
  total_sessions: number;
  risk_score: number;
  ml_anomaly_count?: number;
  ml_risk_score?: number;
  error_message?: string;
  created_at: string;
  updated_at: string;
  tcp_streams?: TCPStream[];
}

export const api = {
  async checkHealth(): Promise<{ status: string; engine: string; tshark_installed: boolean; database?: string }> {
    const res = await fetch(`${API_BASE_URL}/api/health`);
    if (!res.ok) throw new Error("Backend offline");
    return res.json();
  },

  async uploadPCAP(file: File, autoProcess: boolean = true): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch(`${API_BASE_URL}/api/pcap/upload?auto_process=${autoProcess}`, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Upload failed" }));
      throw new Error(err.detail || `Upload failed with HTTP ${res.status}`);
    }

    return res.json();
  },

  async getJobStatus(jobId: string): Promise<JobStatusResponse> {
    const res = await fetch(`${API_BASE_URL}/api/pcap/jobs/${jobId}`);
    if (!res.ok) throw new Error("Failed to fetch job status");
    return res.json();
  },

  async getJobStreams(jobId: string, protocol?: string): Promise<TCPStream[]> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/streams`, base);
    if (protocol && protocol !== "ALL") {
      url.searchParams.set("protocol", protocol);
    }
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch streams");
    return res.json();
  },

  async getStreamHandshake(jobId: string, streamId: string): Promise<TLSHandshakeDetail> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/streams/${streamId}/handshake`, base);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch handshake details");
    return res.json();
  },

  async getJobCertificates(jobId: string): Promise<Certificate[]> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/certificates`, base);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch certificates");
    return res.json();
  },

  async getJobPackets(jobId: string, limit: number = 100, offset: number = 0, protocol?: string): Promise<PacketRecord[]> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/packets`, base);
    url.searchParams.set("limit", limit.toString());
    url.searchParams.set("offset", offset.toString());
    if (protocol && protocol !== "ALL") {
      url.searchParams.set("protocol", protocol);
    }
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch packets");
    return res.json();
  },

  async retryProcessing(jobId: string): Promise<JobStatusResponse> {
    const res = await fetch(`${API_BASE_URL}/api/pcap/jobs/${jobId}/process`, {
      method: "POST",
    });
    if (!res.ok) throw new Error("Failed to trigger processing");
    return res.json();
  },

  async getJobFindings(jobId: string, severity?: string, category?: string): Promise<VulnerabilityFinding[]> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/findings`, base);
    if (severity && severity !== "ALL") {
      url.searchParams.set("severity", severity);
    }
    if (category && category !== "ALL") {
      url.searchParams.set("category", category);
    }
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch vulnerability findings");
    return res.json();
  },

  async getJobRiskSummary(jobId: string): Promise<RiskSummary> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/risk-summary`, base);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch risk summary");
    return res.json();
  },

  async getJobAnomalies(jobId: string): Promise<StreamAnomaly[]> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/anomalies`, base);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch anomalies");
    return res.json();
  },

  async getJobAIInsights(jobId: string): Promise<AIInsights> {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    const url = new URL(`/api/pcap/jobs/${jobId}/ai-insights`, base);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error("Failed to fetch AI insights");
    return res.json();
  },

  getReportJsonUrl(jobId: string): string {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    return `${base}/api/pcap/jobs/${jobId}/report/json`;
  },

  getReportHtmlUrl(jobId: string): string {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    return `${base}/api/pcap/jobs/${jobId}/report/html`;
  },

  getReportPdfUrl(jobId: string): string {
    const base = API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5173");
    return `${base}/api/pcap/jobs/${jobId}/report/pdf`;
  }
};
