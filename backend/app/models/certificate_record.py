import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.database import Base


class CertificateRecord(Base):
    __tablename__ = "certificates"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    stream_id = Column(String(36), ForeignKey("tcp_streams.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint_sha256 = Column(String(64), index=True, nullable=False)
    serial_number = Column(String(64), nullable=True)
    subject_cn = Column(String(255), nullable=False)
    subject_org = Column(String(255), nullable=True)
    issuer_cn = Column(String(255), nullable=False)
    issuer_org = Column(String(255), nullable=True)
    is_self_signed = Column(Boolean, default=False, nullable=False)
    is_expired = Column(Boolean, default=False, nullable=False)
    is_not_yet_valid = Column(Boolean, default=False, nullable=False)
    days_until_expiry = Column(Integer, default=0, nullable=False)
    not_valid_before = Column(String(40), nullable=False)
    not_valid_after = Column(String(40), nullable=False)
    san_dns_names = Column(JSON, nullable=True)
    public_key_algorithm = Column(String(32), nullable=False)
    public_key_bits = Column(Integer, nullable=False)
    is_weak_key = Column(Boolean, default=False, nullable=False)
    signature_algorithm = Column(String(64), nullable=False)
    signature_hash = Column(String(32), nullable=False)
    is_weak_hash = Column(Boolean, default=False, nullable=False)
    chain_position = Column(Integer, default=0, nullable=False)
    raw_der_hex = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    job = relationship("AnalysisJob", back_populates="certificates")
    stream = relationship("TCPStream", back_populates="certificates")
