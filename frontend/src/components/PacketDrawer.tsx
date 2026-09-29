import React, { useEffect, useState } from "react";
import { X, ArrowRight, Lock, Unlock, Key, List } from "lucide-react";
import { api } from "../services/api";
import type { TCPStream, PacketRecord, TLSHandshakeDetail } from "../services/api";
import { HandshakeInspector } from "./HandshakeInspector";

interface PacketDrawerProps {
  stream: TCPStream | null;
  jobId: string;
  onClose: () => void;
}

export const PacketDrawer: React.FC<PacketDrawerProps> = ({ stream, jobId, onClose }) => {
  const [activeTab, setActiveTab] = useState<"packets" | "handshake">("packets");
  const [packets, setPackets] = useState<PacketRecord[]>([]);
  const [handshake, setHandshake] = useState<TLSHandshakeDetail | null>(null);
  const [loadingPackets, setLoadingPackets] = useState(false);
  const [loadingHandshake, setLoadingHandshake] = useState(false);

  useEffect(() => {
    if (!stream) return;

    // Reset tab to handshake if stream is encrypted
    if (stream.is_tls_encrypted) {
      setActiveTab("handshake");
    } else {
      setActiveTab("packets");
    }

    // Load packets
    setLoadingPackets(true);
    api
      .getJobPackets(jobId, 200, 0)
      .then((allPkts) => {
        const streamPkts = allPkts.filter(
          (p) =>
            (p.source_ip === stream.client_ip && p.destination_ip === stream.server_ip) ||
            (p.source_ip === stream.server_ip && p.destination_ip === stream.client_ip)
        );
        setPackets(streamPkts);
      })
      .catch((err) => console.error("Error fetching stream packets:", err))
      .finally(() => setLoadingPackets(false));

    // Load handshake detail
    setLoadingHandshake(true);
    api
      .getStreamHandshake(jobId, stream.id)
      .then((data) => setHandshake(data))
      .catch((err) => console.error("Error fetching handshake detail:", err))
      .finally(() => setLoadingHandshake(false));
  }, [stream, jobId]);

  if (!stream) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span className="badge badge-neutral">Stream #{stream.stream_index}</span>
              <span className="badge badge-info">{stream.protocol}</span>
              {stream.is_tls_encrypted ? (
                <span className="badge badge-success">
                  <Lock size={12} /> {stream.tls_version || "Encrypted TLS"}
                </span>
              ) : (
                <span className="badge badge-danger">
                  <Unlock size={12} /> Plaintext
                </span>
              )}
              {stream.has_pfs && (
                <span className="badge badge-success">PFS</span>
              )}
            </div>
            <div style={{ fontSize: "0.8125rem", color: "var(--text-secondary)", marginTop: "0.375rem" }} className="font-mono">
              {stream.client_ip}:{stream.client_port} <ArrowRight size={12} style={{ display: "inline" }} /> {stream.server_ip}:{stream.server_port}
            </div>
          </div>
          <button className="close-btn" onClick={onClose} aria-label="Close Drawer">
            <X size={20} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{ padding: "0 1.5rem", borderBottom: "1px solid var(--border-default)" }}>
          <div className="tabs-nav" style={{ margin: "0" }}>
            <button
              className={`tab-btn ${activeTab === "handshake" ? "active" : ""}`}
              onClick={() => setActiveTab("handshake")}
            >
              <Key size={15} />
              TLS Handshake & Certificates
            </button>
            <button
              className={`tab-btn ${activeTab === "packets" ? "active" : ""}`}
              onClick={() => setActiveTab("packets")}
            >
              <List size={15} />
              Packet Sequence ({packets.length})
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {activeTab === "handshake" ? (
            <HandshakeInspector handshake={handshake} loading={loadingHandshake} />
          ) : (
            <div>
              {/* Stream Overview Card */}
              <div className="card" style={{ marginBottom: "1rem" }}>
                <div className="card-header" style={{ padding: "0.75rem 1rem" }}>
                  <span className="card-title" style={{ fontSize: "0.875rem" }}>Session Attributes</span>
                </div>
                <div className="card-body" style={{ padding: "0.875rem 1rem", fontSize: "0.8125rem" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", rowGap: "0.5rem" }}>
                    <span style={{ color: "var(--text-muted)" }}>Protocol:</span>
                    <span style={{ fontWeight: 600 }}>{stream.protocol}</span>

                    <span style={{ color: "var(--text-muted)" }}>STARTTLS Upgrade:</span>
                    <span>
                      {stream.has_starttls ? (
                        <span className="badge badge-success">
                          Detected {stream.starttls_packet_index ? `(Packet #${stream.starttls_packet_index})` : ""}
                        </span>
                      ) : (
                        <span className="badge badge-neutral">Not Used / Implicit TLS</span>
                      )}
                    </span>

                    <span style={{ color: "var(--text-muted)" }}>Negotiated Cipher:</span>
                    <span className="font-mono">{stream.cipher_suite || "None (Cleartext or Encrypted in tunnel)"}</span>
                  </div>
                </div>
              </div>

              {/* Packet Timeline Table */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                <h3 style={{ fontSize: "0.875rem", fontWeight: 600 }}>Packet Sequence ({packets.length} packets)</h3>
              </div>

              {loadingPackets ? (
                <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                  Loading stream packets...
                </div>
              ) : packets.length === 0 ? (
                <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                  No individual packet records available for this session.
                </div>
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Time</th>
                        <th>Source → Dest</th>
                        <th>Layer</th>
                        <th>TCP Flags</th>
                        <th>Details / Payload</th>
                      </tr>
                    </thead>
                    <tbody>
                      {packets.map((pkt) => {
                        const isClient = pkt.source_ip === stream.client_ip;
                        return (
                          <tr key={pkt.packet_number}>
                            <td className="font-mono">{pkt.packet_number}</td>
                            <td className="font-mono" style={{ color: "var(--text-muted)" }}>
                              {pkt.timestamp.toFixed(4)}
                            </td>
                            <td className="font-mono">
                              <span style={{ color: isClient ? "var(--primary)" : "#059669", fontWeight: 500 }}>
                                {isClient ? "Client → Server" : "Server → Client"}
                              </span>
                            </td>
                            <td>
                              <span className={`badge ${pkt.protocol === "TLS" ? "badge-success" : pkt.protocol === "TCP" ? "badge-neutral" : "badge-info"}`}>
                                {pkt.protocol}
                              </span>
                            </td>
                            <td className="font-mono">
                              {pkt.tcp_flags ? (
                                <span style={{ fontSize: "0.7rem", color: "var(--text-secondary)" }}>
                                  {pkt.tcp_flags.syn && "[SYN] "}
                                  {pkt.tcp_flags.ack && "[ACK] "}
                                  {pkt.tcp_flags.push && "[PSH] "}
                                  {pkt.tcp_flags.fin && "[FIN] "}
                                  {pkt.tcp_flags.rst && "[RST] "}
                                </span>
                              ) : (
                                "-"
                              )}
                            </td>
                            <td style={{ maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {pkt.tls_info ? (
                                <span className="font-mono" style={{ color: "var(--status-success-text)" }}>
                                  TLS {pkt.tls_info.handshake_type || "Record"} ({pkt.tls_info.version || ""})
                                </span>
                              ) : pkt.smtp_info ? (
                                <span className="font-mono" style={{ color: "var(--text-main)" }}>
                                  {pkt.smtp_info.command || pkt.smtp_info.response || pkt.smtp_info.banner || pkt.smtp_info.sample_text || ""}
                                </span>
                              ) : pkt.imap_info ? (
                                <span className="font-mono" style={{ color: "var(--text-main)" }}>
                                  {pkt.imap_info.command || pkt.imap_info.response || pkt.imap_info.banner || ""}
                                </span>
                              ) : pkt.pop3_info ? (
                                <span className="font-mono" style={{ color: "var(--text-main)" }}>
                                  {pkt.pop3_info.command || pkt.pop3_info.response || pkt.pop3_info.banner || ""}
                                </span>
                              ) : (
                                <span style={{ color: "var(--text-muted)" }}>TCP Segment ({pkt.packet_length} B)</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
