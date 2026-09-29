from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any


class StreamAnomalySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stream_id: str
    stream_index: int
    protocol: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    is_anomaly: bool
    anomaly_score: float
    anomaly_reasons: Optional[List[str]] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    has_pfs: bool = False


class AIInsightsSchema(BaseModel):
    job_id: str
    total_sessions: int
    anomalous_sessions_count: int
    ai_risk_score: int
    ai_verdict: str  # "BASELINE_CONFORMANT" | "MODERATE_DEVIATION" | "HIGH_RISK_ANOMALIES"
    primary_anomaly_vectors: List[str]
    anomalous_streams: List[StreamAnomalySchema]
