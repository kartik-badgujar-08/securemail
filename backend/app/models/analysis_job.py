import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, BigInteger, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from app.database import Base


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), index=True, nullable=False)
    status = Column(String(32), default="QUEUED", nullable=False, index=True)
    parser_engine_used = Column(String(32), nullable=True)
    is_duplicate = Column(Boolean, default=False, nullable=False)
    error_message = Column(Text, nullable=True)
    total_packets = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)
    risk_score = Column(Integer, default=0, nullable=False)  # 0 to 100 risk score
    ml_anomaly_count = Column(Integer, default=0, nullable=False)
    ml_risk_score = Column(Integer, default=0, nullable=False)  # 0 to 100 AI/ML risk score
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    tcp_streams = relationship("TCPStream", back_populates="job", cascade="all, delete-orphan")
    packets = relationship("PacketRecord", back_populates="job", cascade="all, delete-orphan")
    certificates = relationship("CertificateRecord", back_populates="job", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="job", cascade="all, delete-orphan")

    @property
    def job_id(self) -> str:
        return self.id

