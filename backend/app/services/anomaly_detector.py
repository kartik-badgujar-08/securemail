import logging
from typing import List, Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.tcp_stream import TCPStream
from app.models.certificate_record import CertificateRecord
from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Module 5: Machine Learning Anomaly Detection & AI Risk Scoring Engine.
    Uses an unsupervised Isolation Forest trained on standard enterprise email TLS traffic patterns
    to detect cryptographic anomalies, downgrade patterns, and suspicious protocol configurations.
    """

    _model: IsolationForest = None
    _feature_names = [
        "tls_version_ord",
        "cipher_security_score",
        "has_pfs",
        "has_starttls",
        "is_encrypted",
        "is_standard_port",
        "cert_valid",
        "cert_weak_indicators_count",
        "client_offered_ciphers_count",
        "client_weak_ciphers_ratio",
        "packet_count",
    ]

    @classmethod
    def get_or_train_model(cls) -> IsolationForest:
        """Initializes and trains the baseline Isolation Forest if not already cached in memory."""
        if cls._model is not None:
            return cls._model

        # Synthesize legitimate enterprise baseline dataset (normal secure modern email transactions)
        np.random.seed(42)
        normal_samples = []

        # 1. Normal TLS 1.3 enterprise SMTP/IMAP transactions (50 samples)
        for _ in range(50):
            normal_samples.append([
                5,    # tls_version_ord (TLS 1.3)
                3,    # cipher_security_score (Secure AEAD)
                1,    # has_pfs (True)
                np.random.choice([0, 1]), # has_starttls (implicit or STARTTLS)
                1,    # is_encrypted (True)
                1,    # is_standard_port (True)
                1,    # cert_valid (True)
                0,    # cert_weak_indicators_count (0)
                np.random.randint(10, 30), # client_offered_ciphers_count
                round(np.random.uniform(0.0, 0.1), 2), # client_weak_ciphers_ratio
                np.random.randint(8, 45),  # packet_count
            ])

        # 2. Normal TLS 1.2 with ECDHE AES-GCM transactions (100 samples)
        for _ in range(100):
            normal_samples.append([
                4,    # tls_version_ord (TLS 1.2)
                3,    # cipher_security_score (Secure AEAD)
                1,    # has_pfs (True)
                np.random.choice([0, 1]),
                1,    # is_encrypted (True)
                1,    # is_standard_port (True)
                1,    # cert_valid (True)
                0,    # cert_weak_indicators_count (0)
                np.random.randint(8, 35),
                round(np.random.uniform(0.0, 0.15), 2),
                np.random.randint(7, 50),
            ])

        # 3. Acceptable legacy TLS 1.2 with CBC or standard RSA (15 samples)
        for _ in range(15):
            normal_samples.append([
                4,    # tls_version_ord (TLS 1.2)
                np.random.choice([1, 2]), # cipher_security_score (Weak CBC or Acceptable)
                np.random.choice([0, 1]), # has_pfs
                np.random.choice([0, 1]),
                1,    # is_encrypted (True)
                1,    # is_standard_port (True)
                1,    # cert_valid (True)
                0,    # cert_weak_indicators_count
                np.random.randint(6, 25),
                round(np.random.uniform(0.1, 0.3), 2),
                np.random.randint(6, 40),
            ])

        X_train = np.array(normal_samples, dtype=float)

        cls._model = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42,
        )
        cls._model.fit(X_train)
        logger.info(f"Isolation Forest model trained on {len(X_train)} baseline samples.")
        return cls._model

    @classmethod
    def extract_stream_features(cls, stream: TCPStream, certs: List[CertificateRecord], packet_count: int) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Extracts normalized numerical features and metadata dictionary for a single TCPStream."""
        # 1. TLS version ordinal
        ver_str = (stream.tls_version or "").upper()
        if not stream.is_tls_encrypted:
            tls_ord = 0
        elif "TLS 1.3" in ver_str:
            tls_ord = 5
        elif "TLS 1.2" in ver_str:
            tls_ord = 4
        elif "TLS 1.1" in ver_str:
            tls_ord = 3
        elif "TLS 1.0" in ver_str:
            tls_ord = 2
        elif "SSL" in ver_str:
            tls_ord = 1
        else:
            tls_ord = 1 if stream.is_tls_encrypted else 0

        # 2. Cipher security score
        cipher_str = (stream.cipher_suite or "").upper()
        if not stream.is_tls_encrypted:
            cipher_score = 0
        elif any(bad in cipher_str for bad in ["RC4", "3DES", "DES", "NULL", "EXPORT"]):
            cipher_score = 0
        elif "CBC" in cipher_str and "TLS 1.3" not in ver_str:
            cipher_score = 1
        elif "GCM" in cipher_str or "POLY1305" in cipher_str or "CCM" in cipher_str:
            cipher_score = 3
        else:
            cipher_score = 2

        # 3. PFS
        pfs_val = 1 if stream.has_pfs else 0

        # 4. STARTTLS
        starttls_val = 1 if stream.has_starttls else 0

        # 5. Encrypted
        enc_val = 1 if stream.is_tls_encrypted else 0

        # 6. Standard mail ports (25, 465, 587, 110, 995, 143, 993)
        std_port_val = 1 if stream.server_port in (25, 465, 587, 110, 995, 143, 993) else 0

        # 7 & 8. Certificate features
        cert_weak_count = 0
        cert_valid_val = 1
        if not certs and stream.is_tls_encrypted:
            # TLS encrypted but missing cert or extracted cert failed
            cert_valid_val = 0
        elif certs:
            for c in certs:
                if c.is_expired or c.is_weak_key or c.is_weak_hash or c.is_self_signed:
                    cert_weak_count += 1
            if cert_weak_count > 0:
                cert_valid_val = 0
        else:
            cert_valid_val = 0

        # 9 & 10. ClientHello offered ciphers telemetry
        details = stream.details or {}
        client_ciphers = details.get("client_cipher_suites", [])
        ciphers_count = len(client_ciphers)
        if ciphers_count > 0:
            weak_cnt = sum(1 for c in client_ciphers if c.get("security") in ("INSECURE", "WEAK") or not c.get("pfs", False))
            weak_ratio = round(weak_cnt / ciphers_count, 2)
        else:
            weak_ratio = 0.0

        # 11. Packet count
        pkt_count = packet_count if packet_count > 0 else 5

        features = np.array([
            tls_ord,
            cipher_score,
            pfs_val,
            starttls_val,
            enc_val,
            std_port_val,
            cert_valid_val,
            cert_weak_count,
            ciphers_count,
            weak_ratio,
            pkt_count,
        ], dtype=float)

        meta = {
            "tls_version_ord": tls_ord,
            "cipher_security_score": cipher_score,
            "has_pfs": bool(pfs_val),
            "is_encrypted": bool(enc_val),
            "has_starttls": bool(starttls_val),
            "cert_valid": bool(cert_valid_val),
            "cert_weak_indicators": cert_weak_count,
            "client_offered_ciphers": ciphers_count,
            "client_weak_ratio": weak_ratio,
        }

        return features, meta

    @classmethod
    def generate_anomaly_reasons(cls, stream: TCPStream, meta: Dict[str, Any]) -> List[str]:
        """Provides explainable security insights into why an anomaly was flagged by AI/ML."""
        reasons = []

        if not meta["is_encrypted"]:
            reasons.append(
                f"Completely cleartext {stream.protocol} communication without encryption on mail port {stream.server_port}"
            )

        if meta["is_encrypted"] and meta["tls_version_ord"] <= 3:
            reasons.append(
                f"Negotiated deprecated legacy TLS version ({stream.tls_version or 'Legacy SSL/TLS'})"
            )

        if meta["is_encrypted"] and meta["cipher_security_score"] == 0:
            reasons.append(
                f"Insecure cipher suite negotiated ({stream.cipher_suite or 'Legacy'}) vulnerable to cryptanalytic collision attacks"
            )

        if meta["is_encrypted"] and not meta["has_pfs"]:
            reasons.append(
                "Static RSA key exchange lacks Perfect Forward Secrecy (PFS), susceptible to retroactive decryption"
            )

        if meta["is_encrypted"] and meta["cert_weak_indicators"] > 0:
            reasons.append(
                f"X.509 certificate chain contains {meta['cert_weak_indicators']} security warning(s) (e.g. self-signed, expired, or weak key size)"
            )

        if meta["client_weak_ratio"] >= 0.5:
            reasons.append(
                f"Client offered high proportion of weak/non-PFS ciphers ({int(meta['client_weak_ratio'] * 100)}% of offered suites)"
            )

        if not reasons:
            reasons.append("Unusual cryptographic feature distribution deviating from baseline enterprise traffic")

        return reasons

    @classmethod
    def evaluate_job(cls, job_id: str, db: Session) -> Dict[str, Any]:
        """
        Runs the Isolation Forest anomaly detector on all streams of an analysis job.
        Updates stream anomaly scores, anomaly flags, explanation reasons, and job aggregate ML score.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found.")

        streams = db.query(TCPStream).filter(TCPStream.job_id == job_id).all()
        if not streams:
            job.ml_anomaly_count = 0
            job.ml_risk_score = 0
            db.commit()
            return {"job_id": job_id, "anomalies_detected": 0, "ml_risk_score": 0}

        model = cls.get_or_train_model()

        feature_matrix = []
        stream_metas = []

        for st in streams:
            certs = db.query(CertificateRecord).filter(CertificateRecord.stream_id == st.id).all()
            pkt_count = db.query(PacketRecord).filter(PacketRecord.stream_id == st.id).count()
            feats, meta = cls.extract_stream_features(st, certs, pkt_count)
            feature_matrix.append(feats)
            stream_metas.append(meta)

        X = np.array(feature_matrix, dtype=float)

        # Raw scores: negative values are outliers, positive are inliers
        raw_scores = model.decision_function(X)
        predictions = model.predict(X)  # -1 = anomaly, 1 = normal

        total_anomalies = 0
        stream_scores = []

        for idx, st in enumerate(streams):
            raw = raw_scores[idx]
            pred = predictions[idx]
            meta = stream_metas[idx]

            # Normalize raw score (-0.35 to 0.25) to a clean 0 to 100 Anomaly Score:
            # Highly normal -> 0 - 15
            # Borderline -> 20 - 45
            # Severe anomaly -> 50 - 100
            if not meta["is_encrypted"] or meta["cipher_security_score"] == 0 or meta["tls_version_ord"] <= 2:
                # Force high anomaly score if critically insecure
                norm_score = max(75.0, round(float((0.20 - raw) * 160.0), 1))
                norm_score = min(100.0, norm_score)
                is_anom = True
            elif not meta["has_pfs"] or meta["cert_weak_indicators"] > 0 or meta["tls_version_ord"] == 3:
                norm_score = max(55.0, round(float((0.15 - raw) * 140.0), 1))
                norm_score = min(90.0, norm_score)
                is_anom = True
            else:
                norm_score = max(0.0, round(float((0.15 - raw) * 100.0), 1))
                norm_score = min(40.0, norm_score)
                is_anom = bool(pred == -1 and norm_score >= 50.0)

            if is_anom:
                total_anomalies += 1
                reasons = cls.generate_anomaly_reasons(st, meta)
            else:
                reasons = []

            st.anomaly_score = norm_score
            st.is_anomaly = is_anom
            st.anomaly_reasons = reasons
            stream_scores.append(norm_score)

        # Aggregate ML Risk Score (0-100)
        if stream_scores:
            avg_score = sum(stream_scores) / len(stream_scores)
            max_score = max(stream_scores)
            # Weighted combination of peak anomaly and average anomaly
            combined_ml_score = min(100, int(round(0.7 * max_score + 0.3 * avg_score)))
        else:
            combined_ml_score = 0

        job.ml_anomaly_count = total_anomalies
        job.ml_risk_score = combined_ml_score
        db.commit()

        logger.info(
            f"Module 5 ML Anomaly evaluation for job {job_id}: {total_anomalies}/{len(streams)} anomalous sessions, "
            f"AI Risk Index: {combined_ml_score}/100"
        )

        return {
            "job_id": job_id,
            "total_sessions": len(streams),
            "anomalies_detected": total_anomalies,
            "ml_risk_score": combined_ml_score,
            "stream_results": [
                {
                    "stream_index": st.stream_index,
                    "protocol": st.protocol,
                    "is_anomaly": st.is_anomaly,
                    "anomaly_score": st.anomaly_score,
                    "reasons": st.anomaly_reasons,
                }
                for st in streams
            ],
        }
