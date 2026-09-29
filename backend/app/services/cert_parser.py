import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, padding
from cryptography.exceptions import InvalidSignature


class CertificateParser:
    """Parses X.509 ASN.1 DER certificates and validates security properties."""

    @classmethod
    def parse_der_certificate(cls, der_bytes: bytes) -> Dict[str, Any]:
        """Parses raw DER-encoded certificate bytes and returns structured security attributes."""
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            raise ValueError(f"Failed to load X.509 DER certificate: {e}")

        now = datetime.now(timezone.utc)

        # 1. Subject & Issuer extraction
        subject_cn = cls._get_name_attribute(cert.subject, x509.NameOID.COMMON_NAME)
        subject_org = cls._get_name_attribute(cert.subject, x509.NameOID.ORGANIZATION_NAME)
        issuer_cn = cls._get_name_attribute(cert.issuer, x509.NameOID.COMMON_NAME)
        issuer_org = cls._get_name_attribute(cert.issuer, x509.NameOID.ORGANIZATION_NAME)

        # 2. Fingerprints & Serial
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        serial_number = f"{cert.serial_number:X}"

        # 3. Validity Period
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        is_expired = now > not_after
        is_not_yet_valid = now < not_before
        days_until_expiry = (not_after - now).days if not is_expired else 0

        # 4. Subject Alternative Names (SANs)
        san_dns_names: List[str] = []
        san_ips: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ips.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        # 5. Public Key Details & Key Length
        public_key = cert.public_key()
        pk_algo = "UNKNOWN"
        pk_bits = 0
        is_weak_key = False

        if isinstance(public_key, rsa.RSAPublicKey):
            pk_algo = "RSA"
            pk_bits = public_key.key_size
            is_weak_key = pk_bits < 2048  # Deprecated if < 2048
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            pk_algo = "EC"
            pk_bits = public_key.key_size
            is_weak_key = pk_bits < 224
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pk_algo = "EdDSA"
            pk_bits = 256 if isinstance(public_key, ed25519.Ed25519PublicKey) else 448
        elif isinstance(public_key, dsa.DSAPublicKey):
            pk_algo = "DSA"
            pk_bits = public_key.key_size
            is_weak_key = True

        # 6. Signature Algorithm & Digest
        sig_algo_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
        sig_hash_algo = "UNKNOWN"

        if cert.signature_hash_algorithm:
            sig_hash_algo = cert.signature_hash_algorithm.name.upper()

        is_weak_hash = sig_hash_algo in ("MD5", "SHA1")

        # 7. Self-Signed Detection
        is_self_signed = cls._check_self_signed(cert)

        # 8. Key Usage / Ext Key Usage
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass

        return {
            "fingerprint_sha256": fingerprint_sha256,
            "serial_number": serial_number,
            "subject_cn": subject_cn or "UNKNOWN",
            "subject_org": subject_org,
            "issuer_cn": issuer_cn or "UNKNOWN",
            "issuer_org": issuer_org,
            "not_valid_before": not_before.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "days_until_expiry": days_until_expiry,
            "san_dns_names": san_dns_names,
            "san_ips": san_ips,
            "public_key_algorithm": pk_algo,
            "public_key_bits": pk_bits,
            "is_weak_key": is_weak_key,
            "signature_algorithm": sig_algo_name,
            "signature_hash": sig_hash_algo,
            "is_weak_hash": is_weak_hash,
            "is_self_signed": is_self_signed,
            "is_ca": is_ca,
            "raw_der_hex": der_bytes.hex(),
        }

    @staticmethod
    def _get_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
        return None

    @classmethod
    def _check_self_signed(cls, cert: x509.Certificate) -> bool:
        """Determines if a certificate is self-signed by verifying its signature with its own public key."""
        if cert.issuer != cert.subject:
            return False

        public_key = cert.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                return True
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
                return True
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                )
                return True
        except (InvalidSignature, Exception):
            return False

        return False
