import logging
from pathlib import Path
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.analysis_job import AnalysisJob
from app.models.tcp_stream import TCPStream
from app.models.packet_record import PacketRecord
from app.models.certificate_record import CertificateRecord
from app.services.tshark_parser import TSharkParser
from app.services.scapy_parser import ScapyParser
from app.services.vulnerability_engine import VulnerabilityEngine
from app.services.anomaly_detector import AnomalyDetector

logger = logging.getLogger(__name__)


class ProcessingOrchestrator:
    @classmethod
    def process_job(cls, job_id: str, db: Session) -> Dict[str, Any]:
        """
        Executes PCAP dissection on the job's capture file using TShark or Scapy fallback,
        persisting extracted streams, packets, and X.509 certificate chains to the database.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found in database.")

        job.status = "PROCESSING"
        db.commit()

        pcap_path = Path(job.file_path)
        if not pcap_path.is_file():
            job.status = "FAILED"
            job.error_message = f"Capture file not found on disk at {pcap_path}"
            db.commit()
            return {"status": "FAILED", "error": job.error_message}

        engine_used = "tshark" if TSharkParser.is_available() else "scapy"
        job.parser_engine_used = engine_used

        try:
            logger.info(f"Starting analysis for job {job_id} using engine: {engine_used}")
            if engine_used == "tshark":
                packets, streams = TSharkParser.parse_pcap(pcap_path)
            else:
                packets, streams = ScapyParser.parse_pcap(pcap_path)

            # Persist TCP Streams & Certificates
            stream_models: Dict[int, TCPStream] = {}
            total_certs_saved = 0

            for s in streams:
                stream_obj = TCPStream(
                    job_id=job.id,
                    stream_index=s["stream_index"],
                    client_ip=s["client_ip"],
                    client_port=s["client_port"],
                    server_ip=s["server_ip"],
                    server_port=s["server_port"],
                    protocol=s["protocol"],
                    has_starttls=s["has_starttls"],
                    starttls_packet_index=s.get("starttls_packet_index"),
                    is_tls_encrypted=s["is_tls_encrypted"],
                    tls_version=s.get("tls_version"),
                    cipher_suite=s.get("cipher_suite"),
                    has_pfs=s.get("has_pfs", False),
                    key_exchange=s.get("key_exchange"),
                    sni=s.get("sni"),
                    details=s,
                )
                db.add(stream_obj)
                db.flush()  # populate ID
                stream_models[s["stream_index"]] = stream_obj

                # Persist extracted X.509 certificates
                certs = s.get("certificates", [])
                for cert in certs:
                    cert_obj = CertificateRecord(
                        job_id=job.id,
                        stream_id=stream_obj.id,
                        fingerprint_sha256=cert["fingerprint_sha256"],
                        serial_number=cert.get("serial_number"),
                        subject_cn=cert["subject_cn"],
                        subject_org=cert.get("subject_org"),
                        issuer_cn=cert["issuer_cn"],
                        issuer_org=cert.get("issuer_org"),
                        is_self_signed=cert.get("is_self_signed", False),
                        is_expired=cert.get("is_expired", False),
                        is_not_yet_valid=cert.get("is_not_yet_valid", False),
                        days_until_expiry=cert.get("days_until_expiry", 0),
                        not_valid_before=cert["not_valid_before"],
                        not_valid_after=cert["not_valid_after"],
                        san_dns_names=cert.get("san_dns_names", []),
                        public_key_algorithm=cert["public_key_algorithm"],
                        public_key_bits=cert["public_key_bits"],
                        is_weak_key=cert.get("is_weak_key", False),
                        signature_algorithm=cert["signature_algorithm"],
                        signature_hash=cert["signature_hash"],
                        is_weak_hash=cert.get("is_weak_hash", False),
                        chain_position=cert.get("chain_position", 0),
                        raw_der_hex=cert.get("raw_der_hex"),
                    )
                    db.add(cert_obj)
                    total_certs_saved += 1

            # Persist Packet Records
            for p in packets:
                stream_ref = stream_models.get(p.get("stream_index"))
                stream_id = stream_ref.id if stream_ref else None

                pkt_obj = PacketRecord(
                    job_id=job.id,
                    stream_id=stream_id,
                    packet_number=p["packet_number"],
                    timestamp=p["timestamp"],
                    source_ip=p["source_ip"],
                    destination_ip=p["destination_ip"],
                    source_port=p.get("source_port"),
                    destination_port=p.get("destination_port"),
                    protocol=p["protocol"],
                    packet_length=p["packet_length"],
                    tcp_flags=p.get("tcp_flags"),
                    tls_info=p.get("tls_info"),
                    smtp_info=p.get("smtp_info"),
                    imap_info=p.get("imap_info"),
                    pop3_info=p.get("pop3_info"),
                )
                db.add(pkt_obj)

            db.flush()

            # Module 4: Run Vulnerability Rules Engine & Compute Risk Score
            vuln_summary = VulnerabilityEngine.evaluate_job(job.id, db)

            # Module 5: Run AI/ML Anomaly Detection & Compute ML Risk Index
            ml_summary = AnomalyDetector.evaluate_job(job.id, db)

            job.status = "COMPLETED"
            job.total_packets = len(packets)
            job.total_sessions = len(streams)
            db.commit()

            logger.info(
                f"Job {job_id} completed: {len(packets)} packets, {len(streams)} sessions, "
                f"{total_certs_saved} certificates, {vuln_summary['total_findings']} findings (Score: {vuln_summary['risk_score']}), "
                f"{ml_summary['anomalies_detected']} ML anomalies (AI Index: {ml_summary['ml_risk_score']})."
            )
            return {
                "status": "COMPLETED",
                "total_packets": len(packets),
                "total_sessions": len(streams),
                "total_certificates": total_certs_saved,
                "total_findings": vuln_summary["total_findings"],
                "risk_score": vuln_summary["risk_score"],
                "anomalies_detected": ml_summary["anomalies_detected"],
                "ml_risk_score": ml_summary["ml_risk_score"],
                "engine_used": engine_used,
            }

        except Exception as e:
            logger.exception(f"Error processing PCAP for job {job_id}: {e}")
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
            return {"status": "FAILED", "error": str(e)}
