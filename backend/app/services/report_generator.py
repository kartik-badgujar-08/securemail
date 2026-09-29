import io
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.models.analysis_job import AnalysisJob
from app.models.tcp_stream import TCPStream
from app.models.certificate_record import CertificateRecord
from app.models.vulnerability_finding import VulnerabilityFinding


class ReportGenerator:
    """
    Module 6: Executive Reporting & Export Engine.
    Generates structured JSON, printable HTML, and native PDF audit reports.
    """

    @classmethod
    def get_report_data(cls, job_id: str, db: Session) -> Dict[str, Any]:
        """Collects and aggregates all audit data for a capture job."""
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found.")

        streams = db.query(TCPStream).filter(TCPStream.job_id == job_id).order_by(TCPStream.stream_index.asc()).all()
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.job_id == job_id).all()
        certs = db.query(CertificateRecord).filter(CertificateRecord.job_id == job_id).order_by(CertificateRecord.chain_position.asc()).all()

        total_sessions = len(streams)
        smtp_count = sum(1 for s in streams if s.protocol == "SMTP")
        imap_count = sum(1 for s in streams if s.protocol == "IMAP")
        pop3_count = sum(1 for s in streams if s.protocol == "POP3")
        other_proto_count = total_sessions - (smtp_count + imap_count + pop3_count)

        starttls_count = sum(1 for s in streams if s.has_starttls)
        encrypted_count = sum(1 for s in streams if s.is_tls_encrypted)
        cleartext_count = total_sessions - encrypted_count
        pfs_count = sum(1 for s in streams if s.has_pfs)

        tls_13_count = sum(1 for s in streams if s.tls_version and "1.3" in s.tls_version)
        tls_12_count = sum(1 for s in streams if s.tls_version and "1.2" in s.tls_version)
        tls_legacy_count = sum(1 for s in streams if s.tls_version and any(v in s.tls_version for v in ["1.0", "1.1", "SSL"]))

        # Risk Grade & Posture
        score = job.risk_score
        if score == 0:
            grade = "A+"
            level = "SECURE"
        elif score <= 15:
            grade = "A"
            level = "LOW RISK"
        elif score <= 35:
            grade = "B"
            level = "MODERATE RISK"
        elif score <= 60:
            grade = "C"
            level = "HIGH RISK"
        else:
            grade = "F"
            level = "CRITICAL RISK"

        ai_score = job.ml_risk_score
        if ai_score <= 20:
            ai_verdict = "BASELINE_CONFORMANT"
        elif ai_score <= 50:
            ai_verdict = "MODERATE_DEVIATION"
        else:
            ai_verdict = "HIGH_RISK_ANOMALIES"

        crit_cnt = sum(1 for f in findings if f.severity == "CRITICAL")
        high_cnt = sum(1 for f in findings if f.severity == "HIGH")
        med_cnt = sum(1 for f in findings if f.severity == "MEDIUM")
        low_cnt = sum(1 for f in findings if f.severity == "LOW")
        info_cnt = sum(1 for f in findings if f.severity == "INFO")

        severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

        anomalous_streams = [s for s in streams if s.is_anomaly]

        return {
            "metadata": {
                "job_id": job.id,
                "filename": job.filename,
                "file_size_bytes": job.file_size_bytes,
                "sha256_hash": job.sha256_hash,
                "status": job.status,
                "parser_engine_used": job.parser_engine_used or "scapy",
                "is_duplicate": job.is_duplicate,
                "total_packets": job.total_packets,
                "total_sessions": total_sessions,
                "created_at": job.created_at.isoformat() if hasattr(job.created_at, "isoformat") else str(job.created_at) if job.created_at else None,
                "report_generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "executive_summary": {
                "deterministic_risk_score": score,
                "security_grade": grade,
                "risk_level": level,
                "ai_anomaly_index": ai_score,
                "ai_verdict": ai_verdict,
                "total_findings": len(findings),
                "critical_findings": crit_cnt,
                "high_findings": high_cnt,
                "medium_findings": med_cnt,
                "low_findings": low_cnt,
                "info_findings": info_cnt,
                "anomalous_sessions_count": len(anomalous_streams),
            },
            "protocol_statistics": {
                "total_sessions": total_sessions,
                "smtp_sessions": smtp_count,
                "imap_sessions": imap_count,
                "pop3_sessions": pop3_count,
                "other_sessions": other_proto_count,
                "starttls_upgrades": starttls_count,
                "encrypted_sessions": encrypted_count,
                "cleartext_sessions": cleartext_count,
                "pfs_enabled_sessions": pfs_count,
                "tls_version_distribution": {
                    "tls_1_3": tls_13_count,
                    "tls_1_2": tls_12_count,
                    "legacy_tls_ssl": tls_legacy_count,
                },
            },
            "vulnerabilities": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_entity": f.affected_entity,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in sorted_findings
            ],
            "ai_anomalies": [
                {
                    "stream_index": s.stream_index,
                    "protocol": s.protocol,
                    "client_endpoint": f"{s.client_ip}:{s.client_port}",
                    "server_endpoint": f"{s.server_ip}:{s.server_port}",
                    "anomaly_score": s.anomaly_score,
                    "reasons": s.anomaly_reasons or [],
                    "tls_version": s.tls_version,
                    "cipher_suite": s.cipher_suite,
                    "has_pfs": s.has_pfs,
                }
                for s in anomalous_streams
            ],
            "certificates": [
                {
                    "subject_cn": c.subject_cn,
                    "issuer_cn": c.issuer_cn,
                    "fingerprint_sha256": c.fingerprint_sha256,
                    "public_key": f"{c.public_key_algorithm} {c.public_key_bits}-bit",
                    "is_weak_key": c.is_weak_key,
                    "signature_hash": c.signature_hash,
                    "is_weak_hash": c.is_weak_hash,
                    "is_self_signed": c.is_self_signed,
                    "is_expired": c.is_expired,
                    "days_until_expiry": c.days_until_expiry,
                    "valid_until": c.not_valid_after.isoformat() if hasattr(c.not_valid_after, "isoformat") else str(c.not_valid_after) if c.not_valid_after else None,
                    "san_dns_names": c.san_dns_names or [],
                }
                for c in certs
            ],
            "sessions": [
                {
                    "stream_index": s.stream_index,
                    "protocol": s.protocol,
                    "client": f"{s.client_ip}:{s.client_port}",
                    "server": f"{s.server_ip}:{s.server_port}",
                    "has_starttls": s.has_starttls,
                    "is_encrypted": s.is_tls_encrypted,
                    "tls_version": s.tls_version,
                    "cipher_suite": s.cipher_suite,
                    "has_pfs": s.has_pfs,
                    "is_anomaly": s.is_anomaly,
                    "anomaly_score": s.anomaly_score,
                }
                for s in streams
            ],
        }

    @classmethod
    def generate_json_report(cls, job_id: str, db: Session) -> Dict[str, Any]:
        """Returns structured JSON audit report."""
        return cls.get_report_data(job_id, db)

    @classmethod
    def generate_html_report(cls, job_id: str, db: Session) -> str:
        """Generates self-contained print-ready HTML executive report."""
        data = cls.get_report_data(job_id, db)
        meta = data["metadata"]
        exec_sum = data["executive_summary"]
        proto = data["protocol_statistics"]
        vulns = data["vulnerabilities"]
        anomalies = data["ai_anomalies"]
        certs = data["certificates"]

        grade = exec_sum["security_grade"]
        grade_color = "#059669" if grade.startswith("A") else "#ca8a04" if grade.startswith("B") else "#ea580c" if grade.startswith("C") else "#dc2626"
        grade_bg = "#ecfdf5" if grade.startswith("A") else "#fefce8" if grade.startswith("B") else "#fff7ed" if grade.startswith("C") else "#fef2f2"

        findings_rows = ""
        for v in vulns:
            sev_color = "#dc2626" if v["severity"] == "CRITICAL" else "#ea580c" if v["severity"] == "HIGH" else "#ca8a04" if v["severity"] == "MEDIUM" else "#475569"
            findings_rows += f"""
            <div style="border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 12px; padding: 14px; background: #ffffff;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div>
                        <span style="background: {sev_color}15; color: {sev_color}; border: 1px solid {sev_color}40; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px;">{v["severity"]}</span>
                        <span style="background: #f1f5f9; color: #334155; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 6px;">{v["category"]}</span>
                        <strong style="margin-left: 8px; font-size: 14px; color: #0f172a;">{v["title"]}</strong>
                    </div>
                    <span style="font-family: monospace; font-size: 12px; color: #64748b;">{v["affected_entity"]}</span>
                </div>
                <p style="font-size: 13px; color: #475569; margin: 4px 0 8px 0; line-height: 1.4;">{v["description"]}</p>
                <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 8px 12px; border-radius: 4px;">
                    <strong style="font-size: 11px; color: #166534; text-transform: uppercase;">Remediation Guidance:</strong>
                    <div style="font-size: 12px; color: #14532d; margin-top: 2px;">{v["remediation"]}</div>
                </div>
            </div>
            """

        if not vulns:
            findings_rows = "<p style='color: #059669; font-weight: 600; padding: 12px; background: #ecfdf5; border-radius: 6px;'>Zero security vulnerabilities identified. Traffic conforms to modern TLS standards.</p>"

        anomalies_rows = ""
        for a in anomalies:
            reasons_html = "".join([f"<li>{r}</li>" for r in a["reasons"]])
            anomalies_rows += f"""
            <div style="border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 10px; padding: 12px; background: #ffffff;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <strong>Stream #{a["stream_index"]} ({a["protocol"]}) - {a["client_endpoint"]} &rarr; {a["server_endpoint"]}</strong>
                    <span style="background: #f5f3ff; color: #6d28d9; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px;">Anomaly: {a["anomaly_score"]:.1f}%</span>
                </div>
                <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #475569;">
                    {reasons_html}
                </ul>
            </div>
            """

        if not anomalies:
            anomalies_rows = "<p style='color: #059669; font-weight: 600; padding: 12px; background: #ecfdf5; border-radius: 6px;'>Baseline Conformant: No anomalous session patterns detected by Isolation Forest.</p>"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MailSec TLS Executive Security Audit - {meta["filename"]}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #0f172a;
            background: #f8fafc;
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .report-sheet {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .title {{
            font-size: 22px;
            font-weight: 800;
            color: #0f172a;
            margin: 0;
        }}
        .subtitle {{
            font-size: 13px;
            color: #475569;
            margin-top: 4px;
        }}
        .scorecard {{
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .score-box {{
            flex: 1;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            background: #fafbfc;
            text-align: center;
        }}
        .grade-shield {{
            width: 56px;
            height: 56px;
            border-radius: 8px;
            background: {grade_bg};
            color: {grade_color};
            border: 2px solid {grade_color};
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: 800;
            margin: 0 auto 8px auto;
        }}
        table.stats-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            font-size: 13px;
        }}
        table.stats-table th, table.stats-table td {{
            border: 1px solid #e2e8f0;
            padding: 8px 12px;
            text-align: left;
        }}
        table.stats-table th {{
            background: #f1f5f9;
            font-weight: 600;
            color: #334155;
        }}
        .section-title {{
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 6px;
            margin: 24px 0 12px 0;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .report-sheet {{ border: none; box-shadow: none; padding: 0; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="report-sheet">
        <div class="header">
            <div>
                <h1 class="title">Email Protocol Security & TLS Audit Report</h1>
                <div class="subtitle">Platform: MailSec TLS Passive Dissection & AI Anomaly Engine</div>
                <div style="font-size: 11px; color: #64748b; margin-top: 6px;">
                    Target Capture: <strong>{meta["filename"]}</strong> (SHA-256: <code>{meta["sha256_hash"][:16]}...</code>)
                </div>
            </div>
            <div style="text-align: right; font-size: 12px; color: #475569;">
                <div><strong>Audit Date:</strong> {meta["report_generated_at"][:10]}</div>
                <div><strong>Engine:</strong> {meta["parser_engine_used"].upper()}</div>
                <div><strong>Packets:</strong> {meta["total_packets"]} | <strong>Sessions:</strong> {meta["total_sessions"]}</div>
                <div class="no-print" style="margin-top: 8px;">
                    <button onclick="window.print()" style="background: #1e40af; color: #ffffff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600;">Print / Save as PDF</button>
                </div>
            </div>
        </div>

        <div class="scorecard">
            <div class="score-box">
                <div class="grade-shield">{grade}</div>
                <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Security Grade</div>
                <div style="font-size: 14px; font-weight: 700; color: {grade_color};">{exec_sum["risk_level"]}</div>
            </div>
            <div class="score-box">
                <div style="font-size: 28px; font-weight: 800; color: #0f172a; margin-top: 8px;">{exec_sum["deterministic_risk_score"]} <span style="font-size: 14px; color: #64748b;">/ 100</span></div>
                <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">Deterministic Risk Score</div>
                <div style="font-size: 12px; color: #475569;">{exec_sum["total_findings"]} Findings ({exec_sum["critical_findings"]} Critical)</div>
            </div>
            <div class="score-box">
                <div style="font-size: 28px; font-weight: 800; color: #6d28d9; margin-top: 8px;">{exec_sum["ai_anomaly_index"]} <span style="font-size: 14px; color: #64748b;">/ 100</span></div>
                <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase;">AI Anomaly Risk Index</div>
                <div style="font-size: 12px; color: #475569;">{exec_sum["anomalous_sessions_count"]} Flagged Stream(s)</div>
            </div>
        </div>

        <div class="section-title">Protocol & Cryptographic Baseline Telemetry</div>
        <table class="stats-table">
            <tr>
                <th>Protocol Sessions</th>
                <td>SMTP: <strong>{proto["smtp_sessions"]}</strong> | IMAP: <strong>{proto["imap_sessions"]}</strong> | POP3: <strong>{proto["pop3_sessions"]}</strong></td>
                <th>STARTTLS Upgrades</th>
                <td><strong>{proto["starttls_upgrades"]}</strong> / {proto["total_sessions"]} ({int((proto["starttls_upgrades"]/proto["total_sessions"]*100) if proto["total_sessions"] else 0)}%)</td>
            </tr>
            <tr>
                <th>TLS Encryption</th>
                <td>Encrypted: <strong style="color: #059669;">{proto["encrypted_sessions"]}</strong> | Cleartext: <strong style="color: #dc2626;">{proto["cleartext_sessions"]}</strong></td>
                <th>Perfect Forward Secrecy</th>
                <td>PFS Enabled (ECDHE/DHE): <strong>{proto["pfs_enabled_sessions"]}</strong> / {proto["total_sessions"]}</td>
            </tr>
            <tr>
                <th>TLS Version Breakdown</th>
                <td colspan="3">TLS 1.3: <strong>{proto["tls_version_distribution"]["tls_1_3"]}</strong> | TLS 1.2: <strong>{proto["tls_version_distribution"]["tls_1_2"]}</strong> | Deprecated (1.0/1.1/SSL): <strong style="color: #dc2626;">{proto["tls_version_distribution"]["legacy_tls_ssl"]}</strong></td>
            </tr>
        </table>

        <div class="section-title">Deterministic Security Vulnerabilities ({len(vulns)})</div>
        {findings_rows}

        <div class="section-title">AI / Machine Learning Anomaly Detections ({len(anomalies)})</div>
        {anomalies_rows}

        <div class="section-title">X.509 Certificate Chain Inventory ({len(certs)})</div>
        <table class="stats-table">
            <thead>
                <tr>
                    <th>Subject CN</th>
                    <th>Issuer CN</th>
                    <th>Public Key</th>
                    <th>Digest</th>
                    <th>Validity Expiry</th>
                    <th>Self-Signed</th>
                </tr>
            </thead>
            <tbody>
                {"".join([f"<tr><td><strong>{c['subject_cn']}</strong></td><td>{c['issuer_cn']}</td><td>{c['public_key']}</td><td>{c['signature_hash']}</td><td>{c['valid_until'][:10] if c['valid_until'] else 'N/A'} ({c['days_until_expiry']}d)</td><td>{'Yes' if c['is_self_signed'] else 'No'}</td></tr>" for c in certs]) if certs else "<tr><td colspan='6' style='text-align: center; color: #64748b;'>No certificates observed in capture.</td></tr>"}
            </tbody>
        </table>

        <div style="margin-top: 30px; padding-top: 12px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between;">
            <span>Generated by MailSec TLS Auditor - Confidential Security Assessment</span>
            <span>Page 1 of 1</span>
        </div>
    </div>
</body>
</html>"""
        return html

    @classmethod
    def generate_pdf_report(cls, job_id: str, db: Session) -> bytes:
        """Generates native PDF document using ReportLab."""
        data = cls.get_report_data(job_id, db)
        meta = data["metadata"]
        exec_sum = data["executive_summary"]
        proto = data["protocol_statistics"]
        vulns = data["vulnerabilities"]
        anomalies = data["ai_anomalies"]
        certs = data["certificates"]

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom typography styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=0,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            fontName="Helvetica",
        )
        h2_style = ParagraphStyle(
            "H2Style",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica",
        )
        small_bold = ParagraphStyle(
            "SmallBold",
            parent=body_style,
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
        )

        elements = []

        # Header Title
        elements.append(Paragraph("MailSec TLS Executive Security Audit", title_style))
        elements.append(Paragraph(f"Capture: {meta['filename']} | SHA-256: {meta['sha256_hash'][:24]}...", subtitle_style))
        elements.append(Paragraph(f"Audit Generated: {meta['report_generated_at'][:19]} UTC | Engine: {meta['parser_engine_used'].upper()}", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=12))

        # Executive Scorecard Table
        grade = exec_sum["security_grade"]
        score_data = [
            [
                Paragraph("<b>SECURITY GRADE</b>", small_bold),
                Paragraph("<b>DETERMINISTIC RISK SCORE</b>", small_bold),
                Paragraph("<b>AI ANOMALY RISK INDEX</b>", small_bold),
            ],
            [
                Paragraph(f"<font size=20 color='#0f172a'><b>{grade}</b></font><br/>{exec_sum['risk_level']}", body_style),
                Paragraph(f"<font size=20 color='#0f172a'><b>{exec_sum['deterministic_risk_score']}</b></font>/100<br/>{exec_sum['total_findings']} Findings ({exec_sum['critical_findings']} Critical)", body_style),
                Paragraph(f"<font size=20 color='#6d28d9'><b>{exec_sum['ai_anomaly_index']}</b></font>/100<br/>{exec_sum['anomalous_sessions_count']} Flagged Anomalies", body_style),
            ],
        ]
        t_score = Table(score_data, colWidths=[180, 180, 180])
        t_score.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_score)
        elements.append(Spacer(1, 14))

        # Protocol Statistics Table
        elements.append(Paragraph("Protocol & Cryptographic Telemetry", h2_style))
        proto_data = [
            ["Metric", "Value", "Metric", "Value"],
            ["Total Sessions", str(proto["total_sessions"]), "STARTTLS Upgrades", f"{proto['starttls_upgrades']} ({int(proto['starttls_upgrades']/proto['total_sessions']*100) if proto['total_sessions'] else 0}%)"],
            ["SMTP Streams", str(proto["smtp_sessions"]), "TLS Encrypted", str(proto["encrypted_sessions"])],
            ["IMAP / POP3 Streams", f"{proto['imap_sessions']} / {proto['pop3_sessions']}", "Cleartext Insecure", str(proto["cleartext_sessions"])],
            ["PFS Adoption (ECDHE)", str(proto["pfs_enabled_sessions"]), "TLS 1.3 / 1.2 / Legacy", f"{proto['tls_version_distribution']['tls_1_3']} / {proto['tls_version_distribution']['tls_1_2']} / {proto['tls_version_distribution']['legacy_tls_ssl']}"],
        ]
        t_proto = Table(proto_data, colWidths=[135, 135, 135, 135])
        t_proto.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_proto)
        elements.append(Spacer(1, 14))

        # Vulnerabilities Section
        elements.append(Paragraph(f"Security Vulnerability Findings ({len(vulns)})", h2_style))
        if vulns:
            v_data = [["Severity", "Rule ID", "Affected Entity", "Description & Remediation"]]
            for v in vulns[:10]:  # Cap first 10 for clean PDF display
                desc_text = f"<b>{v['title']}</b><br/>{v['description'][:140]}...<br/><font color='#166534'><b>Remediation:</b> {v['remediation'][:100]}...</font>"
                v_data.append([
                    v["severity"],
                    v["rule_id"],
                    Paragraph(v["affected_entity"], body_style),
                    Paragraph(desc_text, body_style),
                ])
            t_vuln = Table(v_data, colWidths=[65, 100, 115, 260])
            t_vuln.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_vuln)
        else:
            elements.append(Paragraph("Zero security vulnerabilities identified. Traffic conforms to modern TLS standards.", body_style))

        elements.append(Spacer(1, 14))

        # AI / ML Anomalies Section
        elements.append(Paragraph(f"AI / Machine Learning Anomalies ({len(anomalies)})", h2_style))
        if anomalies:
            anom_data = [["Stream", "Protocol", "Endpoints", "Anomaly Score", "Primary Reasons"]]
            for a in anomalies[:8]:
                anom_data.append([
                    f"#{a['stream_index']}",
                    a["protocol"],
                    f"{a['client_endpoint']} -> {a['server_endpoint']}",
                    f"{a['anomaly_score']:.1f}%",
                    Paragraph("<br/>".join([f"• {r}" for r in a["reasons"]]), body_style),
                ])
            t_anom = Table(anom_data, colWidths=[40, 50, 150, 70, 230])
            t_anom.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_anom)
        else:
            elements.append(Paragraph("Baseline Conformant: No anomalous session patterns detected by Isolation Forest.", body_style))

        elements.append(Spacer(1, 14))

        # Certificate Chain Inventory
        elements.append(Paragraph(f"X.509 Certificate Inventory ({len(certs)})", h2_style))
        if certs:
            c_data = [["Subject CN", "Issuer CN", "Public Key", "Hash", "Expiry", "Self-Signed"]]
            for c in certs:
                c_data.append([
                    Paragraph(c["subject_cn"], body_style),
                    Paragraph(c["issuer_cn"], body_style),
                    c["public_key"],
                    c["signature_hash"],
                    f"{c['days_until_expiry']} days",
                    "Yes" if c["is_self_signed"] else "No",
                ])
            t_cert = Table(c_data, colWidths=[120, 120, 90, 60, 80, 70])
            t_cert.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_cert)
        else:
            elements.append(Paragraph("No X.509 certificates extracted from capture.", body_style))

        doc.build(elements)
        return buf.getvalue()
