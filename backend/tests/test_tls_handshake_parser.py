from app.services.cipher_suites import (
    CipherSuiteHelper,
    KX_ECDHE,
    KX_DHE,
    KX_RSA,
    KX_TLS13,
    SEC_SECURE,
    SEC_WEAK,
    SEC_INSECURE,
)
from app.services.tls_handshake_parser import TLSHandshakeParser
from tests.test_cert_parser import _generate_test_cert


def test_cipher_suite_pfs_and_security_mapping():
    # TLS 1.3
    c13 = CipherSuiteHelper.get_info(0x1301)
    assert c13["name"] == "TLS_AES_128_GCM_SHA256"
    assert c13["pfs"] is True
    assert c13["kx"] == KX_TLS13
    assert c13["security"] == SEC_SECURE

    # TLS 1.2 ECDHE (PFS = True)
    c_ecdhe = CipherSuiteHelper.get_info(0xC02F)
    assert c_ecdhe["name"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert c_ecdhe["pfs"] is True
    assert c_ecdhe["kx"] == KX_ECDHE
    assert c_ecdhe["security"] == SEC_SECURE

    # DHE (PFS = True)
    c_dhe = CipherSuiteHelper.get_info(0x009E)
    assert c_dhe["pfs"] is True
    assert c_dhe["kx"] == KX_DHE

    # Static RSA (No PFS)
    c_rsa = CipherSuiteHelper.get_info(0x0035)
    assert c_rsa["name"] == "TLS_RSA_WITH_AES_256_CBC_SHA"
    assert c_rsa["pfs"] is False
    assert c_rsa["kx"] == KX_RSA
    assert c_rsa["security"] == SEC_WEAK

    # Deprecated 3DES & RC4 (Insecure)
    c_3des = CipherSuiteHelper.get_info(0x000A)
    assert c_3des["security"] == SEC_INSECURE
    assert c_3des["pfs"] is False

    c_rc4 = CipherSuiteHelper.get_info(0x0005)
    assert c_rc4["security"] == SEC_INSECURE


def test_parse_client_hello_record():
    # Build ClientHello record with SNI extension and 2 cipher suites (0xC02F, 0x0035)
    sni_host = b"mail.company.com"
    sni_ext = (
        b"\x00\x00"  # ext type 0 (SNI)
        + (len(sni_host) + 5).to_bytes(2, "big")  # ext len
        + (len(sni_host) + 3).to_bytes(2, "big")  # server name list len
        + b"\x00"  # name type 0 (host)
        + len(sni_host).to_bytes(2, "big")
        + sni_host
    )
    exts_payload = len(sni_ext).to_bytes(2, "big") + sni_ext

    # Ciphers payload (0xC02F: ECDHE-RSA-AES128-GCM, 0x0035: RSA-AES256-CBC-SHA)
    ciphers_payload = b"\x00\x04\xc0\x2f\x00\x35"
    comp_payload = b"\x01\x00"  # comp len 1, method 0

    ch_body = (
        b"\x03\x03"      # Client version TLS 1.2
        + b"\xAA" * 32   # Random
        + b"\x00"        # Session ID len 0
        + ciphers_payload
        + comp_payload
        + exts_payload
    )

    # Handshake header: type 1 (ClientHello), 3-byte length
    hs_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    # TLS Record header: type 0x16 (Handshake), version 0x0303, length
    record = b"\x16\x03\x03" + len(hs_msg).to_bytes(2, "big") + hs_msg

    parsed = TLSHandshakeParser.parse_tls_record(record)
    assert parsed is not None
    assert parsed["record_version"] == "TLS 1.2"
    assert len(parsed["messages"]) == 1

    ch_data = parsed["messages"][0]["data"]
    assert ch_data["sni"] == "mail.company.com"
    assert ch_data["cipher_suites_count"] == 2
    cipher_names = [c["name"] for c in ch_data["cipher_suites"]]
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in cipher_names
    assert "TLS_RSA_WITH_AES_256_CBC_SHA" in cipher_names


def test_parse_server_hello_and_pfs_negotiation():
    # Build ServerHello with negotiated cipher 0xC02F (ECDHE -> PFS)
    sh_body = (
        b"\x03\x03"      # Server version TLS 1.2
        + b"\xBB" * 32   # Random
        + b"\x00"        # Session ID len 0
        + b"\xc0\x2f"    # Negotiated cipher suite (ECDHE)
        + b"\x00"        # Compression method 0
        + b"\x00\x00"    # Extensions len 0
    )
    hs_msg = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    record = b"\x16\x03\x03" + len(hs_msg).to_bytes(2, "big") + hs_msg

    parsed = TLSHandshakeParser.parse_tls_record(record)
    assert parsed is not None
    sh_data = parsed["messages"][0]["data"]

    assert sh_data["version"] == "TLS 1.2"
    assert sh_data["cipher_suite"]["name"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert sh_data["has_pfs"] is True
    assert sh_data["key_exchange"] == KX_ECDHE
    assert sh_data["security_level"] == SEC_SECURE


def test_parse_certificate_handshake_message():
    # Generate real DER certificate
    cert_der = _generate_test_cert()

    # Format of TLS Certificate message:
    # 3-byte total certificates length
    # For each cert: 3-byte cert length + cert_der
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    cert_msg_body = len(cert_entry).to_bytes(3, "big") + cert_entry

    # Handshake header: type 11 (Certificate), 3-byte length
    hs_msg = b"\x0b" + len(cert_msg_body).to_bytes(3, "big") + cert_msg_body
    record = b"\x16\x03\x03" + len(hs_msg).to_bytes(2, "big") + hs_msg

    parsed = TLSHandshakeParser.parse_tls_record(record)
    assert parsed is not None
    cert_msg = parsed["messages"][0]
    assert cert_msg["type"] == "Certificate"
    assert len(cert_msg["certificates"]) == 1

    cert_info = cert_msg["certificates"][0]
    assert cert_info["subject_cn"] == "mail.testcorp.com"
    assert cert_info["is_self_signed"] is True
    assert cert_info["public_key_bits"] == 2048
