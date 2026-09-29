import uuid
from sqlalchemy import Column, String, Integer, BigInteger, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class PacketRecord(Base):
    __tablename__ = "packet_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    stream_id = Column(String(36), ForeignKey("tcp_streams.id", ondelete="SET NULL"), nullable=True, index=True)
    packet_number = Column(Integer, nullable=False)
    timestamp = Column(Float, nullable=False)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=False)
    packet_length = Column(Integer, nullable=False)
    tcp_flags = Column(JSON, nullable=True)
    tls_info = Column(JSON, nullable=True)
    smtp_info = Column(JSON, nullable=True)
    imap_info = Column(JSON, nullable=True)
    pop3_info = Column(JSON, nullable=True)

    # Relationships
    job = relationship("AnalysisJob", back_populates="packets")
    stream = relationship("TCPStream", back_populates="packets")
