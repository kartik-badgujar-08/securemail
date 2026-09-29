from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any


class CertificateSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    stream_id: Optional[str] = None
    fingerprint_sha256: str
    serial_number: Optional[str] = None
    subject_cn: str
    subject_org: Optional[str] = None
    issuer_cn: str
    issuer_org: Optional[str] = None
    is_self_signed: bool
    is_expired: bool
    is_not_yet_valid: bool
    days_until_expiry: int
    not_valid_before: str
    not_valid_after: str
    san_dns_names: Optional[List[str]] = []
    public_key_algorithm: str
    public_key_bits: int
    is_weak_key: bool
    signature_algorithm: str
    signature_hash: str
    is_weak_hash: bool
    chain_position: int = 0


class TLSHandshakeDetailSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stream_id: str
    stream_index: int
    protocol: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    has_starttls: bool
    is_tls_encrypted: bool
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    has_pfs: bool = False
    key_exchange: Optional[str] = None
    sni: Optional[str] = None
    client_cipher_suites: List[Dict[str, Any]] = []
    certificates: List[CertificateSchema] = []
