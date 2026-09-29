import shutil
import uuid
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, File, UploadFile, BackgroundTasks, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response, JSONResponse
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db, SessionLocal
from app.models.analysis_job import AnalysisJob
from app.models.tcp_stream import TCPStream
from app.models.packet_record import PacketRecord
from app.models.certificate_record import CertificateRecord
from app.models.vulnerability_finding import VulnerabilityFinding
from app.schemas.pcap import (
    UploadResponse,
    JobStatusResponse,
    JobDetailResponse,
    PacketRecordSchema,
    TCPStreamSchema,
)
from app.schemas.certificate import CertificateSchema, TLSHandshakeDetailSchema
from app.schemas.vulnerability import VulnerabilityFindingSchema, RiskSummarySchema
from app.schemas.ml_anomaly import StreamAnomalySchema, AIInsightsSchema
from app.services.pcap_validator import PCAPValidator
from app.services.processing_orchestrator import ProcessingOrchestrator
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/pcap", tags=["PCAP Management & Processing"])


def run_background_processing(job_id: str):
    """Background task runner with dedicated DB session."""
    db = SessionLocal()
    try:
        ProcessingOrchestrator.process_job(job_id, db)
    finally:
        db.close()


@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_pcap(
    file: UploadFile = File(...),
    auto_process: bool = Query(True, description="Automatically trigger processing after upload"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
):
    """
    Module 1: PCAP Upload endpoint.
    Performs validation checks:
    - .pcap / .pcapng extension check
    - File size verification
    - Valid capture header magic bytes check
    - SHA-256 calculation and duplicate capture detection
    Creates an analysis_job with status = QUEUED.
    """
    filename = file.filename or "unknown.pcap"

    # 1. Extension Check
    PCAPValidator.validate_filename_extension(filename)

    # 2. Stream to disk and enforce size limit
    target_filename = f"{uuid.uuid4()}_{filename}"
    destination_path = settings.upload_path / target_filename

    bytes_written = 0
    max_bytes = settings.max_upload_size_bytes

    try:
        with open(destination_path, "wb") as out_file:
            while chunk := await file.read(65536):
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload exceeded maximum permitted size of {settings.MAX_UPLOAD_SIZE_MB} MB."
                    )
                out_file.write(chunk)
    except Exception:
        if destination_path.exists():
            destination_path.unlink()
        raise

    # 3. Magic Bytes, File Size, and SHA-256 Check
    try:
        sha256_hash, file_size, capture_format = PCAPValidator.compute_sha256_and_validate(destination_path)
    except Exception:
        if destination_path.exists():
            destination_path.unlink()
        raise

    # 4. Duplicate Check (Option B: flag/warn duplicate, create new job)
    existing_duplicate = db.query(AnalysisJob).filter(AnalysisJob.sha256_hash == sha256_hash).first()
    is_duplicate = existing_duplicate is not None

    warning_msg = (
        f"Notice: Capture SHA-256 ({sha256_hash[:12]}...) matches existing job {existing_duplicate.id}. "
        "Created new analysis job (Option B)."
        if is_duplicate
        else f"Valid {capture_format} capture uploaded successfully."
    )

    # 5. Create Analysis Job (status = QUEUED)
    job_id = str(uuid.uuid4())
    job = AnalysisJob(
        id=job_id,
        filename=filename,
        file_path=str(destination_path),
        file_size_bytes=file_size,
        sha256_hash=sha256_hash,
        status="QUEUED",
        is_duplicate=is_duplicate,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Automatically queue processing if requested
    if auto_process:
        background_tasks.add_task(run_background_processing, job.id)

    return UploadResponse(
        job_id=job.id,
        filename=job.filename,
        file_size_bytes=job.file_size_bytes,
        sha256_hash=job.sha256_hash,
        status=job.status,
        is_duplicate=job.is_duplicate,
        message=warning_msg,
    )


@router.post("/jobs/{job_id}/process", response_model=JobStatusResponse)
def trigger_job_processing(
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Manually trigger or restart PCAP processing for a specific job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    job.status = "QUEUED"
    job.error_message = None
    db.commit()
    db.refresh(job)

    background_tasks.add_task(run_background_processing, job.id)
    return job


@router.get("/jobs/{job_id}", response_model=JobDetailResponse)
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """Fetch status, parsed streams, and summary metrics for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job


@router.get("/jobs/{job_id}/streams", response_model=List[TCPStreamSchema])
def list_job_streams(
    job_id: str,
    protocol: Optional[str] = Query(None, description="Filter by protocol: SMTP, IMAP, POP3"),
    db: Session = Depends(get_db),
):
    """Fetch reconstructed TCP sessions with STARTTLS and protocol classification."""
    query = db.query(TCPStream).filter(TCPStream.job_id == job_id)
    if protocol:
        query = query.filter(TCPStream.protocol == protocol.upper())
    return query.order_by(TCPStream.stream_index.asc()).all()


@router.get("/jobs/{job_id}/packets", response_model=List[PacketRecordSchema])
def list_job_packets(
    job_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Fetch extracted packet metadata, TCP flags, and protocol layers."""
    query = db.query(PacketRecord).filter(PacketRecord.job_id == job_id)
    if protocol:
        query = query.filter(PacketRecord.protocol == protocol.upper())
    return query.order_by(PacketRecord.packet_number.asc()).offset(offset).limit(limit).all()


@router.get("/jobs/{job_id}/certificates", response_model=List[CertificateSchema])
def list_job_certificates(
    job_id: str,
    is_expired: Optional[bool] = Query(None),
    is_weak_key: Optional[bool] = Query(None),
    is_self_signed: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
):
    """Module 3: Lists all extracted X.509 certificates and validation attributes for a PCAP capture."""
    query = db.query(CertificateRecord).filter(CertificateRecord.job_id == job_id)
    if is_expired is not None:
        query = query.filter(CertificateRecord.is_expired == is_expired)
    if is_weak_key is not None:
        query = query.filter(CertificateRecord.is_weak_key == is_weak_key)
    if is_self_signed is not None:
        query = query.filter(CertificateRecord.is_self_signed == is_self_signed)

    return query.order_by(CertificateRecord.chain_position.asc()).all()


@router.get("/jobs/{job_id}/streams/{stream_id}/handshake", response_model=TLSHandshakeDetailSchema)
def get_stream_handshake_detail(
    job_id: str,
    stream_id: str,
    db: Session = Depends(get_db),
):
    """Module 3: Fetches deep TLS Handshake analysis for a stream including ClientHello ciphers, ServerHello PFS, and cert chain."""
    stream = db.query(TCPStream).filter(TCPStream.job_id == job_id, TCPStream.id == stream_id).first()
    if not stream:
        raise HTTPException(status_code=404, detail="TCP stream not found")

    certs = db.query(CertificateRecord).filter(CertificateRecord.stream_id == stream_id).order_by(CertificateRecord.chain_position.asc()).all()

    # Extract client cipher suites from stream details if stored
    stream_details = stream.details or {}
    client_ciphers = stream_details.get("client_cipher_suites", [])

    return TLSHandshakeDetailSchema(
        stream_id=stream.id,
        stream_index=stream.stream_index,
        protocol=stream.protocol,
        client_ip=stream.client_ip,
        client_port=stream.client_port,
        server_ip=stream.server_ip,
        server_port=stream.server_port,
        has_starttls=stream.has_starttls,
        is_tls_encrypted=stream.is_tls_encrypted,
        tls_version=stream.tls_version,
        cipher_suite=stream.cipher_suite,
        has_pfs=stream.has_pfs,
        key_exchange=stream.key_exchange,
        sni=stream.sni,
        client_cipher_suites=client_ciphers,
        certificates=certs,
    )


@router.get("/jobs/{job_id}/findings", response_model=List[VulnerabilityFindingSchema])
def list_job_findings(
    job_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    category: Optional[str] = Query(None, description="Filter by category: PROTOCOL, CIPHER, KEY_EXCHANGE, CERTIFICATE"),
    db: Session = Depends(get_db),
):
    """Module 4: Lists all security vulnerability findings identified by the rules engine for a job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    query = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.job_id == job_id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity.upper())
    if category:
        query = query.filter(VulnerabilityFinding.category == category.upper())

    # Sort critical first, then high, medium, low, info
    severity_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
    }
    findings = query.all()
    return sorted(findings, key=lambda f: severity_order.get(f.severity, 99))


@router.get("/jobs/{job_id}/risk-summary", response_model=RiskSummarySchema)
def get_job_risk_summary(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 4: Computes aggregated executive risk posture, grade (A/B/C/F), and severity metrics."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.job_id == job_id).all()

    crit_cnt = sum(1 for f in findings if f.severity == "CRITICAL")
    high_cnt = sum(1 for f in findings if f.severity == "HIGH")
    med_cnt = sum(1 for f in findings if f.severity == "MEDIUM")
    low_cnt = sum(1 for f in findings if f.severity == "LOW")
    info_cnt = sum(1 for f in findings if f.severity == "INFO")

    score = job.risk_score
    if score == 0:
        grade = "A+"
        level = "SECURE"
    elif score <= 15:
        grade = "A"
        level = "LOW RISK"
    elif score <= 35:
        grade = "B"
        level = "MODERATE RISK"
    elif score <= 60:
        grade = "C"
        level = "HIGH RISK"
    else:
        grade = "F"
        level = "CRITICAL RISK"

    return RiskSummarySchema(
        job_id=job.id,
        risk_score=score,
        risk_grade=grade,
        risk_level=level,
        total_findings=len(findings),
        critical_count=crit_cnt,
        high_count=high_cnt,
        medium_count=med_cnt,
        low_count=low_cnt,
        info_count=info_cnt,
    )


@router.get("/jobs/{job_id}/anomalies", response_model=List[StreamAnomalySchema])
def list_job_anomalies(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 5: Returns all TCP streams flagged as anomalous by the AI/ML Isolation Forest."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    anomalous_streams = (
        db.query(TCPStream)
        .filter(TCPStream.job_id == job_id, TCPStream.is_anomaly == True)
        .order_by(TCPStream.anomaly_score.desc())
        .all()
    )

    return [
        StreamAnomalySchema(
            stream_id=st.id,
            stream_index=st.stream_index,
            protocol=st.protocol,
            client_ip=st.client_ip,
            client_port=st.client_port,
            server_ip=st.server_ip,
            server_port=st.server_port,
            is_anomaly=st.is_anomaly,
            anomaly_score=st.anomaly_score,
            anomaly_reasons=st.anomaly_reasons or [],
            tls_version=st.tls_version,
            cipher_suite=st.cipher_suite,
            has_pfs=st.has_pfs,
        )
        for st in anomalous_streams
    ]


@router.get("/jobs/{job_id}/ai-insights", response_model=AIInsightsSchema)
def get_job_ai_insights(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 5: Returns executive AI anomaly telemetry, verdict, and feature explanations."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    all_streams = db.query(TCPStream).filter(TCPStream.job_id == job_id).all()
    anomalous_streams = [s for s in all_streams if s.is_anomaly]

    # Collect top anomaly vectors across sessions
    vectors_set = set()
    for s in anomalous_streams:
        for r in (s.anomaly_reasons or []):
            vectors_set.add(r)

    ai_score = job.ml_risk_score
    if ai_score <= 20:
        verdict = "BASELINE_CONFORMANT"
    elif ai_score <= 50:
        verdict = "MODERATE_DEVIATION"
    else:
        verdict = "HIGH_RISK_ANOMALIES"

    stream_schemas = [
        StreamAnomalySchema(
            stream_id=st.id,
            stream_index=st.stream_index,
            protocol=st.protocol,
            client_ip=st.client_ip,
            client_port=st.client_port,
            server_ip=st.server_ip,
            server_port=st.server_port,
            is_anomaly=st.is_anomaly,
            anomaly_score=st.anomaly_score,
            anomaly_reasons=st.anomaly_reasons or [],
            tls_version=st.tls_version,
            cipher_suite=st.cipher_suite,
            has_pfs=st.has_pfs,
        )
        for st in sorted(anomalous_streams, key=lambda s: s.anomaly_score, reverse=True)
    ]

    return AIInsightsSchema(
        job_id=job.id,
        total_sessions=len(all_streams),
        anomalous_sessions_count=len(anomalous_streams),
        ai_risk_score=ai_score,
        ai_verdict=verdict,
        primary_anomaly_vectors=sorted(list(vectors_set)),
        anomalous_streams=stream_schemas,
    )


@router.get("/jobs/{job_id}/report/json")
def get_job_report_json(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 6: Exports complete audit findings and telemetry as structured JSON."""
    data = ReportGenerator.generate_json_report(job_id, db)
    filename = data["metadata"]["filename"].replace(".pcapng", "").replace(".pcap", "")
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="MailSec_Audit_{filename}.json"'},
    )


@router.get("/jobs/{job_id}/report/html", response_class=HTMLResponse)
def get_job_report_html(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 6: Renders an executive printable HTML audit document."""
    html_content = ReportGenerator.generate_html_report(job_id, db)
    return HTMLResponse(content=html_content)


@router.get("/jobs/{job_id}/report/pdf")
def get_job_report_pdf(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Module 6: Generates and streams a native executive PDF audit document."""
    pdf_bytes = ReportGenerator.generate_pdf_report(job_id, db)
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    clean_name = (job.filename if job else "capture").replace(".pcapng", "").replace(".pcap", "")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="MailSec_Audit_{clean_name}.pdf"'},
    )



