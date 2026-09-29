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
from app.services.anomaly_detector import AnomalyDetector


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


def test_feature_extraction():
    """Validates that numerical feature extraction accurately maps protocol and TLS parameters."""
    job_id = str(uuid.uuid4())
    stream_clean = TCPStream(
        id=str(uuid.uuid4()),
        job_id=job_id,
        stream_index=1,
        client_ip="10.0.0.1",
        client_port=49152,
        server_ip="10.0.0.25",
        server_port=587,
        protocol="SMTP",
        has_starttls=True,
        is_tls_encrypted=True,
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="ECDHE",
    )

    cert = CertificateRecord(
        job_id=job_id,
        stream_id=stream_clean.id,
        fingerprint_sha256="aa" * 32,
        subject_cn="smtp.example.com",
        issuer_cn="DigiCert Global CA",
        is_self_signed=False,
        is_expired=False,
        is_not_yet_valid=False,
        days_until_expiry=120,
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

    feats, meta = AnomalyDetector.extract_stream_features(stream_clean, [cert], 15)
    assert meta["tls_version_ord"] == 4  # TLS 1.2
    assert meta["cipher_security_score"] == 3  # AES-GCM
    assert meta["has_pfs"] is True
    assert meta["cert_valid"] is True
    assert meta["cert_weak_indicators"] == 0
    assert len(feats) == 11


def test_evaluate_job_detects_anomalies(db_session):
    """Verifies that Isolation Forest flags cleartext and deprecated sessions while keeping modern sessions normal."""
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        filename="test_anomalies.pcap",
        file_path="/tmp/test_anomalies.pcap",
        file_size_bytes=4096,
        sha256_hash="hash_ml_1",
        status="PROCESSING",
    )
    db_session.add(job)
    db_session.commit()

    # Stream 1: Completely normal secure TLS 1.2 session
    s1 = TCPStream(
        job_id=job.id,
        stream_index=1,
        client_ip="192.168.1.5",
        client_port=51200,
        server_ip="192.168.1.1",
        server_port=587,
        protocol="SMTP",
        has_starttls=True,
        is_tls_encrypted=True,
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        has_pfs=True,
        key_exchange="ECDHE",
    )
    db_session.add(s1)
    db_session.flush()

    c1 = CertificateRecord(
        job_id=job.id,
        stream_id=s1.id,
        fingerprint_sha256="11" * 32,
        subject_cn="mail.corp.com",
        issuer_cn="CA Corp",
        is_self_signed=False,
        is_expired=False,
        is_not_yet_valid=False,
        days_until_expiry=90,
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
    db_session.add(c1)

    # Stream 2: Anomalous unencrypted cleartext SMTP session
    s2 = TCPStream(
        job_id=job.id,
        stream_index=2,
        client_ip="192.168.1.10",
        client_port=51201,
        server_ip="192.168.1.1",
        server_port=25,
        protocol="SMTP",
        has_starttls=False,
        is_tls_encrypted=False,
    )
    db_session.add(s2)
    db_session.commit()

    result = AnomalyDetector.evaluate_job(job.id, db_session)

    assert result["total_sessions"] == 2
    assert result["anomalies_detected"] >= 1
    assert result["ml_risk_score"] >= 50

    # Verify stream 1 vs stream 2 flags
    db_session.refresh(s1)
    db_session.refresh(s2)

    assert s1.is_anomaly is False
    assert s1.anomaly_score < 45.0

    assert s2.is_anomaly is True
    assert s2.anomaly_score >= 70.0
    assert len(s2.anomaly_reasons) > 0
    assert any("cleartext" in r.lower() for r in s2.anomaly_reasons)


def test_ai_insights_and_anomalies_endpoints(client, db_session):
    """Tests the /jobs/{id}/anomalies and /jobs/{id}/ai-insights REST endpoints."""
    job = AnalysisJob(
        id=str(uuid.uuid4()),
        filename="test_api_ml.pcap",
        file_path="/tmp/test_api_ml.pcap",
        file_size_bytes=2048,
        sha256_hash="hash_ml_api",
        status="PROCESSING",
    )
    db_session.add(job)
    db_session.commit()

    stream = TCPStream(
        job_id=job.id,
        stream_index=1,
        client_ip="10.10.10.2",
        client_port=44555,
        server_ip="10.10.10.1",
        server_port=25,
        protocol="SMTP",
        has_starttls=False,
        is_tls_encrypted=False,
    )
    db_session.add(stream)
    db_session.commit()

    AnomalyDetector.evaluate_job(job.id, db_session)

    # 1. Test /anomalies endpoint
    resp_anomalies = client.get(f"/api/pcap/jobs/{job.id}/anomalies")
    assert resp_anomalies.status_code == 200
    data_anomalies = resp_anomalies.json()
    assert len(data_anomalies) == 1
    assert data_anomalies[0]["is_anomaly"] is True
    assert data_anomalies[0]["anomaly_score"] >= 70.0

    # 2. Test /ai-insights endpoint
    resp_insights = client.get(f"/api/pcap/jobs/{job.id}/ai-insights")
    assert resp_insights.status_code == 200
    data_insights = resp_insights.json()
    assert data_insights["job_id"] == job.id
    assert data_insights["total_sessions"] == 1
    assert data_insights["anomalous_sessions_count"] == 1
    assert data_insights["ai_risk_score"] >= 50
    assert data_insights["ai_verdict"] in ("MODERATE_DEVIATION", "HIGH_RISK_ANOMALIES")
    assert len(data_insights["primary_anomaly_vectors"]) >= 1
