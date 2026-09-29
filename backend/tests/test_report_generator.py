import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.models.analysis_job import AnalysisJob
from app.models.tcp_stream import TCPStream
from app.models.certificate_record import CertificateRecord
from app.models.vulnerability_finding import VulnerabilityFinding
from app.services.report_generator import ReportGenerator


TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_audit_job(db_session):
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        filename="audit_sample.pcap",
        file_path="/tmp/audit_sample.pcap",
        file_size_bytes=8192,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="COMPLETED",
        parser_engine_used="scapy",
        total_packets=24,
        total_sessions=2,
        risk_score=75,
        ml_anomaly_count=1,
        ml_risk_score=80,
    )
    db_session.add(job)
    db_session.flush()

    s1 = TCPStream(
        id=str(uuid.uuid4()),
        job_id=job.id,
        stream_index=1,
        client_ip="192.168.1.10",
        client_port=49500,
        server_ip="192.168.1.25",
        server_port=587,
        protocol="SMTP",
        has_starttls=True,
        is_tls_encrypted=True,
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="ECDHE",
        is_anomaly=False,
        anomaly_score=15.0,
    )
    s2 = TCPStream(
        id=str(uuid.uuid4()),
        job_id=job.id,
        stream_index=2,
        client_ip="192.168.1.11",
        client_port=49501,
        server_ip="192.168.1.25",
        server_port=25,
        protocol="SMTP",
        has_starttls=False,
        is_tls_encrypted=False,
        is_anomaly=True,
        anomaly_score=85.0,
        anomaly_reasons=["Completely cleartext SMTP communication without encryption on mail port 25"],
    )
    db_session.add_all([s1, s2])
    db_session.flush()

    finding = VulnerabilityFinding(
        job_id=job.id,
        stream_id=s2.id,
        rule_id="RULE_CLEARTEXT_EMAIL",
        title="Cleartext SMTP Session Transmitted Without Encryption",
        severity="CRITICAL",
        category="PROTOCOL",
        affected_entity="Stream #2 (192.168.1.11 -> 192.168.1.25:25)",
        description="The SMTP session was transmitted unencrypted.",
        remediation="Enforce mandatory TLS encryption on mail servers.",
        evidence={"protocol": "SMTP"},
    )
    db_session.add(finding)

    cert = CertificateRecord(
        job_id=job.id,
        stream_id=s1.id,
        fingerprint_sha256="cc" * 32,
        subject_cn="mail.example.org",
        issuer_cn="Global Root CA",
        is_self_signed=False,
        is_expired=False,
        is_not_yet_valid=False,
        days_until_expiry=180,
        not_valid_before=datetime.now(timezone.utc),
        not_valid_after=datetime.now(timezone.utc),
        public_key_algorithm="RSA",
        public_key_bits=2048,
        is_weak_key=False,
        signature_algorithm="sha256WithRSAEncryption",
        signature_hash="SHA256",
        is_weak_hash=False,
        chain_position=0,
    )
    db_session.add(cert)
    db_session.commit()

    return job


def test_generate_json_report_structure(db_session, sample_audit_job):
    """Verifies that JSON report generation contains all required sections and telemetry metrics."""
    report = ReportGenerator.generate_json_report(sample_audit_job.id, db_session)

    assert "metadata" in report
    assert report["metadata"]["filename"] == "audit_sample.pcap"
    assert report["metadata"]["total_sessions"] == 2

    assert "executive_summary" in report
    assert report["executive_summary"]["deterministic_risk_score"] == 75
    assert report["executive_summary"]["security_grade"] == "F"
    assert report["executive_summary"]["ai_anomaly_index"] == 80
    assert report["executive_summary"]["critical_findings"] == 1

    assert "protocol_statistics" in report
    assert report["protocol_statistics"]["smtp_sessions"] == 2
    assert report["protocol_statistics"]["starttls_upgrades"] == 1
    assert report["protocol_statistics"]["cleartext_sessions"] == 1

    assert len(report["vulnerabilities"]) == 1
    assert len(report["ai_anomalies"]) == 1
    assert len(report["certificates"]) == 1
    assert len(report["sessions"]) == 2


def test_generate_html_report_markup(db_session, sample_audit_job):
    """Verifies printable HTML report generation and essential CSS / markup components."""
    html_output = ReportGenerator.generate_html_report(sample_audit_job.id, db_session)

    assert "<!DOCTYPE html>" in html_output
    assert "MailSec TLS Executive Security Audit" in html_output
    assert "audit_sample.pcap" in html_output
    assert "Cleartext SMTP Session Transmitted Without Encryption" in html_output
    assert "window.print()" in html_output
    assert "@media print" in html_output


def test_generate_pdf_report_binary(db_session, sample_audit_job):
    """Verifies that ReportLab successfully builds and returns a valid binary PDF document."""
    pdf_bytes = ReportGenerator.generate_pdf_report(sample_audit_job.id, db_session)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")


def test_report_api_endpoints(client, sample_audit_job):
    """Verifies REST endpoints for JSON, HTML, and PDF export."""
    job_id = sample_audit_job.id

    # 1. JSON Report Endpoint
    resp_json = client.get(f"/api/pcap/jobs/{job_id}/report/json")
    assert resp_json.status_code == 200
    assert resp_json.headers["content-type"] == "application/json"
    assert "attachment; filename=" in resp_json.headers["content-disposition"]
    data = resp_json.json()
    assert data["metadata"]["job_id"] == job_id

    # 2. HTML Report Endpoint
    resp_html = client.get(f"/api/pcap/jobs/{job_id}/report/html")
    assert resp_html.status_code == 200
    assert "text/html" in resp_html.headers["content-type"]
    assert "MailSec TLS Executive Security Audit" in resp_html.text

    # 3. PDF Report Endpoint
    resp_pdf = client.get(f"/api/pcap/jobs/{job_id}/report/pdf")
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in resp_pdf.headers["content-disposition"]
    assert resp_pdf.content.startswith(b"%PDF-")
