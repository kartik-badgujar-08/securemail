import React, { useState } from "react";
import { Search, Filter, Lock, Unlock, Eye, ShieldCheck, ShieldAlert, Sparkles, CheckCircle2 } from "lucide-react";
import type { TCPStream } from "../services/api";

interface StreamTableProps {
  streams: TCPStream[];
  onSelectStream: (stream: TCPStream) => void;
  isLoading: boolean;
}

export const StreamTable: React.FC<StreamTableProps> = ({ streams, onSelectStream, isLoading }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [encryptionFilter, setEncryptionFilter] = useState("ALL");

  const filteredStreams = streams.filter((s) => {
    // Search filter
    const matchesSearch =
      s.client_ip.includes(searchTerm) ||
      s.server_ip.includes(searchTerm) ||
      s.client_port.toString().includes(searchTerm) ||
      s.server_port.toString().includes(searchTerm) ||
      (s.cipher_suite && s.cipher_suite.toLowerCase().includes(searchTerm.toLowerCase()));

    // Protocol filter
    const matchesProtocol = protocolFilter === "ALL" || s.protocol === protocolFilter;

    // Encryption filter
    let matchesEncryption = true;
    if (encryptionFilter === "ENCRYPTED") matchesEncryption = s.is_tls_encrypted;
    if (encryptionFilter === "CLEARTEXT") matchesEncryption = !s.is_tls_encrypted;
    if (encryptionFilter === "STARTTLS") matchesEncryption = s.has_starttls;

    return matchesSearch && matchesProtocol && matchesEncryption;
  });

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Filter size={18} />
          Reconstructed Email Sessions ({streams.length})
        </h2>
        <span className="badge badge-neutral font-mono">
          Showing {filteredStreams.length} of {streams.length}
        </span>
      </div>

      <div className="card-body">
        {/* Search & Filter Toolbar */}
        <div className="toolbar">
          <div className="search-input-group">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search by IP, port, or cipher..."
              className="search-input"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div className="filter-group">
            <label style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 500 }}>
              Protocol:
            </label>
            <select
              className="select-input"
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
            >
              <option value="ALL">All Protocols</option>
              <option value="SMTP">SMTP (25 / 587)</option>
              <option value="IMAP">IMAP (143 / 993)</option>
              <option value="POP3">POP3 (110 / 995)</option>
            </select>

            <label style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", fontWeight: 500, marginLeft: "0.5rem" }}>
              Encryption:
            </label>
            <select
              className="select-input"
              value={encryptionFilter}
              onChange={(e) => setEncryptionFilter(e.target.value)}
            >
              <option value="ALL">All Security States</option>
              <option value="ENCRYPTED">TLS Encrypted</option>
              <option value="CLEARTEXT">Plaintext Only</option>
              <option value="STARTTLS">STARTTLS Negotiated</option>
            </select>
          </div>
        </div>

        {/* Sessions Table */}
        {isLoading ? (
          <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
            Loading sessions...
          </div>
        ) : filteredStreams.length === 0 ? (
          <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
            {streams.length === 0
              ? "No email sessions detected in this PCAP. Please upload an SMTP, IMAP, or POP3 capture."
              : "No sessions match the selected filters."}
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Stream</th>
                  <th>Protocol</th>
                  <th>Client Endpoint</th>
                  <th>Server Endpoint</th>
                  <th>STARTTLS</th>
                  <th>TLS State</th>
                  <th>Key Exchange (PFS)</th>
                  <th>Cipher Suite</th>
                  <th>AI Posture</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredStreams.map((stream) => (
                  <tr key={stream.id}>
                    <td className="font-mono">
                      <strong>#{stream.stream_index}</strong>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          stream.protocol === "SMTP"
                            ? "badge-info"
                            : stream.protocol === "IMAP"
                            ? "badge-neutral"
                            : stream.protocol === "POP3"
                            ? "badge-warning"
                            : "badge-outline"
                        }`}
                      >
                        {stream.protocol}
                      </span>
                    </td>
                    <td className="font-mono">
                      {stream.client_ip}:{stream.client_port}
                    </td>
                    <td className="font-mono">
                      {stream.server_ip}:{stream.server_port}
                    </td>
                    <td>
                      {stream.has_starttls ? (
                        <span className="badge badge-success">
                          <ShieldCheck size={12} /> Yes {stream.starttls_packet_index ? `(Pkt #${stream.starttls_packet_index})` : ""}
                        </span>
                      ) : (
                        <span className="badge badge-outline">None</span>
                      )}
                    </td>
                    <td>
                      {stream.is_tls_encrypted ? (
                        <span className="badge badge-success">
                          <Lock size={12} /> {stream.tls_version || "Encrypted"}
                        </span>
                      ) : (
                        <span className="badge badge-danger">
                          <Unlock size={12} /> Cleartext
                        </span>
                      )}
                    </td>
                    <td>
                      {stream.is_tls_encrypted ? (
                        stream.has_pfs ? (
                          <span className="badge badge-success">
                            <ShieldCheck size={12} /> {stream.key_exchange || "PFS"}
                          </span>
                        ) : (
                          <span className="badge badge-warning">
                            <ShieldAlert size={12} /> No PFS ({stream.key_exchange || "RSA"})
                          </span>
                        )
                      ) : (
                        <span className="badge badge-outline">N/A</span>
                      )}
                    </td>
                    <td className="font-mono" style={{ maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {stream.cipher_suite || <span style={{ color: "var(--text-muted)" }}>-</span>}
                    </td>
                    <td>
                      {stream.is_anomaly ? (
                        <span
                          className="badge badge-ai-anomaly"
                          title={(stream.anomaly_reasons || []).join(" | ")}
                        >
                          <Sparkles size={11} /> Anomaly ({Math.round(stream.anomaly_score || 0)}%)
                        </span>
                      ) : (
                        <span className="badge badge-ai-normal">
                          <CheckCircle2 size={11} style={{ color: "#10b981", display: "inline" }} /> Normal
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => onSelectStream(stream)}
                        title="Inspect stream packets and payloads"
                      >
                        <Eye size={14} />
                        Inspect
                      </button>
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
};
