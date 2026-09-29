from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from scapy.all import Ether, IP, TCP, Raw, wrpcap


def generate_vulnerable_sample():
    captures_dir = Path("sample_captures")
    captures_dir.mkdir(exist_ok=True)
    pcap_path = captures_dir / "smtp_vulnerable_sample.pcap"

    packets = []

    # ==========================================
    # Stream 0: Completely Cleartext SMTP on Port 25
    # ==========================================
    client_ip_1 = "192.168.1.110"
    server_ip_1 = "192.168.1.25"
    client_port_1 = 49152
    server_port_1 = 25

    # 3-way handshake
    p1 = Ether() / IP(src=client_ip_1, dst=server_ip_1) / TCP(sport=client_port_1, dport=server_port_1, flags="S", seq=1000)
    p2 = Ether() / IP(src=server_ip_1, dst=client_ip_1) / TCP(sport=server_port_1, dport=client_port_1, flags="SA", seq=2000, ack=1001)
    p3 = Ether() / IP(src=client_ip_1, dst=server_ip_1) / TCP(sport=client_port_1, dport=server_port_1, flags="A", seq=1001, ack=2001)
    packets.extend([p1, p2, p3])

    # Server Banner
    banner = b"220 mail.insecure-bank.org ESMTP Postfix (Ubuntu)\r\n"
    p4 = Ether() / IP(src=server_ip_1, dst=client_ip_1) / TCP(sport=server_port_1, dport=client_port_1, flags="PA", seq=2001, ack=1001) / Raw(load=banner)
    packets.append(p4)

    # Client EHLO
    ehlo = b"EHLO workstation.insecure-bank.org\r\n"
    p5 = Ether() / IP(src=client_ip_1, dst=server_ip_1) / TCP(sport=client_port_1, dport=server_port_1, flags="PA", seq=1001, ack=2001 + len(banner)) / Raw(load=ehlo)
    packets.append(p5)

    # Server 250 response without STARTTLS capability
    ehlo_resp = b"250-mail.insecure-bank.org\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n"
    p6 = Ether() / IP(src=server_ip_1, dst=client_ip_1) / TCP(sport=server_port_1, dport=client_port_1, flags="PA", seq=2001 + len(banner), ack=1001 + len(ehlo)) / Raw(load=ehlo_resp)
    packets.append(p6)

    # Client MAIL FROM & Cleartext message
    mail_data = (
        b"MAIL FROM:<ceo@insecure-bank.org>\r\n"
        b"RCPT TO:<finance@insecure-bank.org>\r\n"
        b"DATA\r\n"
        b"Subject: Q3 Sensitive Payroll & Wire Instructions\r\n"
        b"From: ceo@insecure-bank.org\r\n"
        b"To: finance@insecure-bank.org\r\n\r\n"
        b"Please transfer $2,500,000 to routing 021000021 account 88392019.\r\n"
        b"Confidential Credentials: admin / Passw0rd123!\r\n.\r\n"
        b"QUIT\r\n"
    )
    p7 = Ether() / IP(src=client_ip_1, dst=server_ip_1) / TCP(sport=client_port_1, dport=server_port_1, flags="PA", seq=1001 + len(ehlo), ack=2001 + len(banner) + len(ehlo_resp)) / Raw(load=mail_data)
    packets.append(p7)

    # ==========================================
    # Stream 1: SMTP with Deprecated TLS 1.0, 3DES Cipher (Sweet32), Expired Self-Signed Weak 1024-bit Cert
    # ==========================================
    client_ip_2 = "192.168.1.112"
    server_ip_2 = "192.168.1.80"
    client_port_2 = 50210
    server_port_2 = 587

    # Handshake
    p8 = Ether() / IP(src=client_ip_2, dst=server_ip_2) / TCP(sport=client_port_2, dport=server_port_2, flags="S", seq=3000)
    p9 = Ether() / IP(src=server_ip_2, dst=client_ip_2) / TCP(sport=server_port_2, dport=client_port_2, flags="SA", seq=4000, ack=3001)
    p10 = Ether() / IP(src=client_ip_2, dst=server_ip_2) / TCP(sport=client_port_2, dport=server_port_2, flags="A", seq=3001, ack=4001)
    packets.extend([p8, p9, p10])

    # Banner + STARTTLS
    banner_2 = b"220 mail.legacy-corp.com ESMTP Exim 4.80\r\n"
    p11 = Ether() / IP(src=server_ip_2, dst=client_ip_2) / TCP(sport=server_port_2, dport=client_port_2, flags="PA", seq=4001, ack=3001) / Raw(load=banner_2)
    starttls_cmd = b"STARTTLS\r\n"
    p12 = Ether() / IP(src=client_ip_2, dst=server_ip_2) / TCP(sport=client_port_2, dport=server_port_2, flags="PA", seq=3001, ack=4001 + len(banner_2)) / Raw(load=starttls_cmd)
    starttls_ok = b"220 2.0.0 Ready to start TLS\r\n"
    p13 = Ether() / IP(src=server_ip_2, dst=client_ip_2) / TCP(sport=server_port_2, dport=client_port_2, flags="PA", seq=4001 + len(banner_2), ack=3001 + len(starttls_cmd)) / Raw(load=starttls_ok)
    packets.extend([p11, p12, p13])

    # Generate an expired self-signed 1024-bit RSA cert with SHA-1
    key_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.legacy-corp.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Legacy Corp Systems"),
    ])
    # Expired 200 days ago
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key_1024.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=600))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=200))
        .sign(key_1024, hashes.SHA256())
    )
    cert_der = expired_cert.public_bytes(Encoding.DER)

    # TLS 1.0 ClientHello offering 3DES
    client_random = b"\x11" * 32
    # 0x000a = TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ciphers_bytes = b"\x00\x02\x00\x0a"
    comp_bytes = b"\x01\x00"
    chello_body = b"\x03\x01" + client_random + b"\x00" + ciphers_bytes + comp_bytes
    chello_rec = b"\x16\x03\x01" + len(chello_body + b"\x01\x00" + bytes([len(chello_body) >> 8, len(chello_body) & 0xFF])).to_bytes(2, "big")
    chello_hs = b"\x01" + (len(chello_body)).to_bytes(3, "big") + chello_body
    p14 = Ether() / IP(src=client_ip_2, dst=server_ip_2) / TCP(sport=client_port_2, dport=server_port_2, flags="PA", seq=3001 + len(starttls_cmd), ack=4001 + len(banner_2) + len(starttls_ok)) / Raw(load=b"\x16\x03\x01" + len(chello_hs).to_bytes(2, "big") + chello_hs)
    packets.append(p14)

    # TLS 1.0 ServerHello negotiating 3DES
    server_random = b"\x22" * 32
    shello_body = b"\x03\x01" + server_random + b"\x00\x00\x0a\x00"
    shello_hs = b"\x02" + len(shello_body).to_bytes(3, "big") + shello_body

    # Certificate Handshake Message
    cert_item = len(cert_der).to_bytes(3, "big") + cert_der
    certs_list = len(cert_item).to_bytes(3, "big") + cert_item
    cert_hs = b"\x0b" + len(certs_list).to_bytes(3, "big") + certs_list

    tls_server_payload = (
        b"\x16\x03\x01" + len(shello_hs).to_bytes(2, "big") + shello_hs +
        b"\x16\x03\x01" + len(cert_hs).to_bytes(2, "big") + cert_hs
    )
    p15 = Ether() / IP(src=server_ip_2, dst=client_ip_2) / TCP(sport=server_port_2, dport=client_port_2, flags="PA", seq=4001 + len(banner_2) + len(starttls_ok), ack=3001 + len(starttls_cmd) + len(chello_hs) + 5) / Raw(load=tls_server_payload)
    packets.append(p15)

    wrpcap(str(pcap_path), packets)
    print(f"Generated vulnerable sample PCAP with {len(packets)} packets at {pcap_path}")


if __name__ == "__main__":
    generate_vulnerable_sample()
