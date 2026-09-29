from pydantic import BaseModel, ConfigDict, Field, AliasChoices
from typing import Optional, List, Dict, Any
from datetime import datetime


class UploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(validation_alias=AliasChoices("job_id", "id"))
    filename: str
    file_size_bytes: int
    sha256_hash: str
    status: str
    is_duplicate: bool
    message: str


class JobStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(validation_alias=AliasChoices("job_id", "id"))
    filename: str
    file_size_bytes: int
    sha256_hash: str
    status: str
    parser_engine_used: Optional[str] = None
    is_duplicate: bool = False
    total_packets: int = 0
    total_sessions: int = 0
    risk_score: int = 0
    ml_anomaly_count: int = 0
    ml_risk_score: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PacketRecordSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    packet_number: int
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    packet_length: int
    tcp_flags: Optional[Dict[str, Any]] = None
    tls_info: Optional[Dict[str, Any]] = None
    smtp_info: Optional[Dict[str, Any]] = None
    imap_info: Optional[Dict[str, Any]] = None
    pop3_info: Optional[Dict[str, Any]] = None


class TCPStreamSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    stream_index: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    has_starttls: bool
    starttls_packet_index: Optional[int] = None
    is_tls_encrypted: bool
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    has_pfs: bool = False
    key_exchange: Optional[str] = None
    sni: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    anomaly_reasons: Optional[List[str]] = None


class JobDetailResponse(JobStatusResponse):
    tcp_streams: List[TCPStreamSchema] = []

