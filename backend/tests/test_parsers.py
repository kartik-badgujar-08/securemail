import tempfile
from pathlib import Path
from scapy.all import IP, TCP, Raw, wrpcap
from app.services.scapy_parser import ScapyParser


def test_scapy_parser_with_smtp_starttls_stream():
    """Generates a synthetic PCAP containing an SMTP session with STARTTLS and validates extraction."""
    packets = []
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.25"
    client_port = 45678
    server_port = 587

    # 1. 3-way Handshake: SYN, SYN-ACK, ACK
    p1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    p2 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001)
    p3 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
    packets.extend([p1, p2, p3])

    # 2. Server Banner: 220 mail.example.com ESMTP
    p4 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001, ack=1001) / Raw(load=b"220 mail.example.com ESMTP Postfix\r\n")
    packets.append(p4)

    # 3. Client: EHLO client.example.com
    p5 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=2037) / Raw(load=b"EHLO client.example.com\r\n")
    packets.append(p5)

    # 4. Server: 250-STARTTLS
    p6 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2037, ack=1027) / Raw(load=b"250-STARTTLS\r\n250 OK\r\n")
    packets.append(p6)

    # 5. Client: STARTTLS
    p7 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1027, ack=2060) / Raw(load=b"STARTTLS\r\n")
    packets.append(p7)

    # 6. Server: 220 2.0.0 Ready to start TLS
    p8 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2060, ack=1037) / Raw(load=b"220 2.0.0 Ready to start TLS\r\n")
    packets.append(p8)

    # 7. Client: TLS ClientHello record (Content type 0x16, TLS 1.2 [0x03, 0x03], length 45, Handshake Type 1 ClientHello)
    dummy_tls_client_hello = (
        b"\x16"          # Handshake Record
        b"\x03\x03"      # TLS 1.2
        b"\x00\x28"      # Length = 40
        b"\x01"          # Handshake type = ClientHello
        b"\x00\x00\x24"  # Handshake length = 36
        b"\x03\x03"      # Version TLS 1.2
        + b"\x00" * 32   # Random
        + b"\x00"        # Session ID length 0
    )
    p9 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1037, ack=2090) / Raw(load=dummy_tls_client_hello)
    packets.append(p9)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_pcap = Path(tmp.name)

    try:
        wrpcap(str(tmp_pcap), packets)

        # Dissect PCAP using ScapyParser
        extracted_pkts, streams = ScapyParser.parse_pcap(tmp_pcap)

        # Verify extracted packets count
        assert len(extracted_pkts) == 9

        # Check packet fields
        first_pkt = extracted_pkts[0]
        assert first_pkt["source_ip"] == client_ip
        assert first_pkt["destination_ip"] == server_ip
        assert first_pkt["source_port"] == client_port
        assert first_pkt["destination_port"] == server_port
        assert "tcp_flags" in first_pkt
        assert first_pkt["tcp_flags"]["syn"] is True
        assert first_pkt["packet_length"] > 0

        # Check TLS Handshake packet detection
        tls_pkt = extracted_pkts[8]
        assert tls_pkt["protocol"] == "TLS"
        assert tls_pkt["tls_info"] is not None
        assert tls_pkt["tls_info"]["version"] == "TLS 1.2"
        assert tls_pkt["tls_info"]["handshake_type"] == "ClientHello"

        # Check stream reconstruction
        assert len(streams) == 1
        stream = streams[0]
        assert stream["protocol"] == "SMTP"
        assert stream["has_starttls"] is True
        assert stream["is_tls_encrypted"] is True
        assert stream["tls_version"] == "TLS 1.2"

    finally:
        if tmp_pcap.exists():
            tmp_pcap.unlink()
