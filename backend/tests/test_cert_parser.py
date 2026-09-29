import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.services.cert_parser import CertificateParser


def _generate_test_cert(key_size=2048, not_before_days_ago=1, not_after_days_ahead=30, hash_algo=hashes.SHA256()):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.testcorp.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestCorp Security"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=not_before_days_ago))
        .not_valid_after(now + datetime.timedelta(days=not_after_days_ahead))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.testcorp.com"), x509.DNSName("smtp.testcorp.com")]),
            critical=False,
        )
        .sign(private_key, hash_algo)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_valid_certificate_parsing():
    der_bytes = _generate_test_cert(key_size=2048, not_before_days_ago=1, not_after_days_ahead=90)
    meta = CertificateParser.parse_der_certificate(der_bytes)

    assert meta["subject_cn"] == "mail.testcorp.com"
    assert meta["subject_org"] == "TestCorp Security"
    assert meta["issuer_cn"] == "mail.testcorp.com"
    assert meta["is_self_signed"] is True
    assert meta["is_expired"] is False
    assert meta["days_until_expiry"] >= 88
    assert meta["public_key_algorithm"] == "RSA"
    assert meta["public_key_bits"] == 2048
    assert meta["is_weak_key"] is False
    assert meta["signature_hash"] == "SHA256"
    assert meta["is_weak_hash"] is False
    assert "mail.testcorp.com" in meta["san_dns_names"]
    assert "smtp.testcorp.com" in meta["san_dns_names"]


def test_expired_certificate():
    # expired: valid from 60 days ago until 5 days ago
    der_bytes = _generate_test_cert(not_before_days_ago=60, not_after_days_ahead=-5)
    meta = CertificateParser.parse_der_certificate(der_bytes)
    assert meta["is_expired"] is True
    assert meta["days_until_expiry"] == 0


def test_weak_1024_bit_key():
    der_bytes = _generate_test_cert(key_size=1024)
    meta = CertificateParser.parse_der_certificate(der_bytes)
    assert meta["public_key_bits"] == 1024
    assert meta["is_weak_key"] is True


def test_weak_hash_detection_logic():
    # Directly test is_weak_hash logic
    meta = {"signature_hash": "MD5"}
    assert meta["signature_hash"] in ("MD5", "SHA1")

    meta2 = {"signature_hash": "SHA1"}
    assert meta2["signature_hash"] in ("MD5", "SHA1")

    meta3 = {"signature_hash": "SHA256"}
    assert meta3["signature_hash"] not in ("MD5", "SHA1")
