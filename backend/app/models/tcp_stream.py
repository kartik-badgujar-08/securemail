import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class TCPStream(Base):
    __tablename__ = "tcp_streams"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    stream_index = Column(Integer, nullable=False)
    client_ip = Column(String(45), nullable=False)
    client_port = Column(Integer, nullable=False)
    server_ip = Column(String(45), nullable=False)
    server_port = Column(Integer, nullable=False)
    protocol = Column(String(32), default="UNKNOWN", nullable=False)  # SMTP, IMAP, POP3, UNKNOWN
    has_starttls = Column(Boolean, default=False, nullable=False)
    starttls_packet_index = Column(Integer, nullable=True)
    is_tls_encrypted = Column(Boolean, default=False, nullable=False)
    tls_version = Column(String(32), nullable=True)
    cipher_suite = Column(String(128), nullable=True)
    has_pfs = Column(Boolean, default=False, nullable=False)
    key_exchange = Column(String(32), nullable=True)
    sni = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    is_anomaly = Column(Boolean, default=False, nullable=False)
    anomaly_reasons = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    job = relationship("AnalysisJob", back_populates="tcp_streams")
    packets = relationship("PacketRecord", back_populates="stream")
    certificates = relationship("CertificateRecord", back_populates="stream", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="stream", cascade="all, delete-orphan")
