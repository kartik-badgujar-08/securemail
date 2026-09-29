import React from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Key,
  AlertTriangle,
  Award,
  Layers,
} from "lucide-react";
import type { TLSHandshakeDetail, Certificate } from "../services/api";

interface HandshakeInspectorProps {
  handshake: TLSHandshakeDetail | null;
  loading: boolean;
}

export const HandshakeInspector: React.FC<HandshakeInspectorProps> = ({ handshake, loading }) => {
  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
        Loading TLS handshake and certificate dissection...
      </div>
    );
  }

  if (!handshake || !handshake.is_tls_encrypted) {
    return (
      <div className="alert alert-warning" style={{ marginTop: "1rem" }}>
        <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
        <div>
          <strong>Unencrypted Session:</strong> This session did not complete or negotiate TLS encryption.
          Email traffic and credentials were transmitted in cleartext.
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* Handshake & Key Exchange Summary */}
      <div className="card">
        <div className="card-header" style={{ padding: "0.875rem 1.25rem" }}>
          <span className="card-title" style={{ fontSize: "0.875rem" }}>
            <Key size={16} /> Negotiated Cryptographic Parameters
          </span>
          <span
            className={`badge ${
              handshake.has_pfs ? "badge-success" : "badge-warning"
            }`}
          >
            {handshake.has_pfs ? "Perfect Forward Secrecy (PFS)" : "No Forward Secrecy"}
          </span>
        </div>
        <div className="card-body" style={{ padding: "1.25rem" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
            <div>
              <div className="stat-label">TLS Protocol</div>
              <div style={{ fontWeight: 600, fontSize: "1rem" }}>{handshake.tls_version || "TLS 1.2"}</div>
              <div className="stat-sub">
                {handshake.tls_version?.includes("1.3") ? "Modern standard" : "Legacy protocol"}
              </div>
            </div>

            <div>
              <div className="stat-label">Key Exchange Method</div>
              <div style={{ fontWeight: 600, fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.375rem" }}>
                {handshake.has_pfs ? (
                  <ShieldCheck size={16} style={{ color: "var(--status-success-text)" }} />
                ) : (
                  <ShieldAlert size={16} style={{ color: "var(--status-warning-text)" }} />
                )}
                {handshake.key_exchange || "UNKNOWN"}
              </div>
              <div className="stat-sub">
                {handshake.has_pfs
                  ? "Ephemeral keys protect past sessions"
                  : "Static RSA: compromised key decrypts history"}
              </div>
            </div>

            <div>
              <div className="stat-label">Server Name Indication (SNI)</div>
              <div className="font-mono" style={{ fontWeight: 600, fontSize: "0.9375rem" }}>
                {handshake.sni || <span style={{ color: "var(--text-muted)" }}>None (Not advertised)</span>}
              </div>
              <div className="stat-sub">Target mail hostname</div>
            </div>
          </div>

          <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid var(--border-default)" }}>
            <div className="stat-label" style={{ marginBottom: "0.25rem" }}>Negotiated Cipher Suite</div>
            <div className="font-mono" style={{ fontWeight: 600, color: "var(--primary)" }}>
              {handshake.cipher_suite || "None"}
            </div>
          </div>
        </div>
      </div>

      {/* X.509 Certificate Chain Inspection */}
      <div className="card">
        <div className="card-header" style={{ padding: "0.875rem 1.25rem" }}>
          <span className="card-title" style={{ fontSize: "0.875rem" }}>
            <Award size={16} /> X.509 Certificate Chain ({handshake.certificates.length} Certs)
          </span>
        </div>
        <div className="card-body" style={{ padding: "1.25rem" }}>
          {handshake.certificates.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
              No certificate message was captured in this session slice (may have been renegotiated or completed in earlier packet).
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              {handshake.certificates.map((cert: Certificate, idx: number) => (
                <div
                  key={cert.id || idx}
                  style={{
                    border: "1px solid var(--border-default)",
                    borderRadius: "var(--radius-md)",
                    padding: "1rem",
                    backgroundColor: "var(--bg-app)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span className="badge badge-neutral">
                        {cert.chain_position === 0 ? "Leaf / End-Entity" : `Intermediate CA #${cert.chain_position}`}
                      </span>
                      {cert.is_self_signed && (
                        <span className="badge badge-warning">
                          <AlertTriangle size={12} /> Self-Signed
                        </span>
                      )}
                      {cert.is_expired ? (
                        <span className="badge badge-danger">EXPIRED</span>
                      ) : (
                        <span className="badge badge-success">Valid ({cert.days_until_expiry} days left)</span>
                      )}
                    </div>
                    <span className="font-mono" style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      SHA256: {cert.fingerprint_sha256.slice(0, 16)}...
                    </span>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", rowGap: "0.375rem", fontSize: "0.8125rem" }}>
                    <span style={{ color: "var(--text-muted)" }}>Subject CN:</span>
                    <strong className="font-mono">{cert.subject_cn}</strong>

                    <span style={{ color: "var(--text-muted)" }}>Issuer CN:</span>
                    <span className="font-mono">{cert.issuer_cn}</span>

                    <span style={{ color: "var(--text-muted)" }}>Public Key:</span>
                    <span>
                      <span className="font-mono">{cert.public_key_algorithm} {cert.public_key_bits}-bit</span>{" "}
                      {cert.is_weak_key && (
                        <span className="badge badge-danger" style={{ marginLeft: "0.5rem" }}>
                          Weak Key (&lt;2048 bit)
                        </span>
                      )}
                    </span>

                    <span style={{ color: "var(--text-muted)" }}>Signature Hash:</span>
                    <span>
                      <span className="font-mono">{cert.signature_hash} ({cert.signature_algorithm})</span>{" "}
                      {cert.is_weak_hash && (
                        <span className="badge badge-danger" style={{ marginLeft: "0.5rem" }}>
                          Weak Digest ({cert.signature_hash})
                        </span>
                      )}
                    </span>

                    <span style={{ color: "var(--text-muted)" }}>Validity:</span>
                    <span className="font-mono" style={{ fontSize: "0.75rem" }}>
                      {cert.not_valid_before.slice(0, 10)} to {cert.not_valid_after.slice(0, 10)}
                    </span>
                  </div>

                  {cert.san_dns_names && cert.san_dns_names.length > 0 && (
                    <div style={{ marginTop: "0.75rem", paddingTop: "0.75rem", borderTop: "1px dashed var(--border-default)" }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.375rem" }}>
                        Subject Alternative Names (SANs):
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.375rem" }}>
                        {cert.san_dns_names.map((dns, dIdx) => (
                          <span key={dIdx} className="badge badge-neutral font-mono" style={{ fontSize: "0.7rem" }}>
                            {dns}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Client Offered Cipher Suites */}
      {handshake.client_cipher_suites && handshake.client_cipher_suites.length > 0 && (
        <div className="card">
          <div className="card-header" style={{ padding: "0.875rem 1.25rem" }}>
            <span className="card-title" style={{ fontSize: "0.875rem" }}>
              <Layers size={16} /> Client Offered Cipher Suites ({handshake.client_cipher_suites.length})
            </span>
          </div>
          <div className="card-body" style={{ padding: "0" }}>
            <div className="table-container" style={{ border: "none", borderRadius: "0" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Hex</th>
                    <th>Cipher Suite Name</th>
                    <th>Key Exchange</th>
                    <th>Forward Secrecy</th>
                    <th>Security Level</th>
                  </tr>
                </thead>
                <tbody>
                  {handshake.client_cipher_suites.map((cs, cIdx) => (
                    <tr key={cIdx}>
                      <td className="font-mono">{cs.hex_code}</td>
                      <td className="font-mono">
                        <strong style={{ color: cs.name === handshake.cipher_suite ? "var(--primary)" : "inherit" }}>
                          {cs.name} {cs.name === handshake.cipher_suite ? " (Negotiated)" : ""}
                        </strong>
                      </td>
                      <td className="font-mono">{cs.kx}</td>
                      <td>
                        {cs.pfs ? (
                          <span className="badge badge-success">PFS</span>
                        ) : (
                          <span className="badge badge-neutral">No PFS</span>
                        )}
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            cs.security === "SECURE"
                              ? "badge-success"
                              : cs.security === "ACCEPTABLE"
                              ? "badge-neutral"
                              : cs.security === "WEAK"
                              ? "badge-warning"
                              : "badge-danger"
                          }`}
                        >
                          {cs.security}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
