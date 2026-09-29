from app.services.protocol_identifier import ProtocolIdentifier


def test_identify_by_port():
    assert ProtocolIdentifier.identify_protocol_by_port(12345, 25) == "SMTP"
    assert ProtocolIdentifier.identify_protocol_by_port(587, 44321) == "SMTP"
    assert ProtocolIdentifier.identify_protocol_by_port(143, 50000) == "IMAP"
    assert ProtocolIdentifier.identify_protocol_by_port(993, 50000) == "IMAP"
    assert ProtocolIdentifier.identify_protocol_by_port(110, 50000) == "POP3"
    assert ProtocolIdentifier.identify_protocol_by_port(995, 50000) == "POP3"
    assert ProtocolIdentifier.identify_protocol_by_port(80, 50000) == "UNKNOWN"


def test_inspect_smtp_signatures():
    proto, info = ProtocolIdentifier.inspect_payload_signature(b"220 mail.secure-corp.com ESMTP Postfix\r\n")
    assert proto == "SMTP"
    assert "banner" in info

    proto, info = ProtocolIdentifier.inspect_payload_signature(b"STARTTLS\r\n")
    assert proto == "SMTP"
    assert info.get("command") == "STARTTLS"

    proto, info = ProtocolIdentifier.inspect_payload_signature(b"220 2.0.0 Ready to start TLS\r\n")
    assert proto == "SMTP"
    assert info.get("response") == "220_READY_FOR_TLS"


def test_inspect_imap_signatures():
    proto, info = ProtocolIdentifier.inspect_payload_signature(b"* OK [CAPABILITY IMAP4rev1] Courier-IMAP ready.\r\n")
    assert proto == "IMAP"
    assert "banner" in info

    proto, info = ProtocolIdentifier.inspect_payload_signature(b"a001 STARTTLS\r\n")
    assert proto == "IMAP"
    assert info.get("command") == "STARTTLS"

    proto, info = ProtocolIdentifier.inspect_payload_signature(b"a001 OK Begin TLS negotiation now\r\n")
    assert proto == "IMAP"
    assert info.get("response") == "OK_BEGIN_TLS"


def test_inspect_pop3_signatures():
    proto, info = ProtocolIdentifier.inspect_payload_signature(b"+OK Dovecot ready.\r\n")
    assert proto == "POP3"
    assert "banner" in info

    proto, info = ProtocolIdentifier.inspect_payload_signature(b"STLS\r\n")
    assert proto == "POP3"
    assert info.get("command") == "STLS"


def test_detect_stream_protocol():
    payloads = [
        b"220 mail.example.com ESMTP\r\n",
        b"EHLO client.example.com\r\n",
        b"250-STARTTLS\r\n250 OK\r\n",
        b"STARTTLS\r\n",
        b"220 2.0.0 Ready to start TLS\r\n",
    ]
    proto, has_st, st_idx = ProtocolIdentifier.detect_stream_protocol(54321, 587, payloads)
    assert proto == "SMTP"
    assert has_st is True
    assert st_idx == 4
