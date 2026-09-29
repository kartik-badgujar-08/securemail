import datetime
from pathlib import Path
from scapy.all import IP, TCP, Raw, wrpcap
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_sample_smtp_tls_pcap(output_file: str = "sample_smtp_tls.pcap"):
    """Generates a realistic PCAP with SMTP STARTTLS, ECDHE PFS key exchange, and X.509 certificate."""
    # 1. Generate RSA key & certificate
    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "smtp.corp-secure.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp Secure Mail Ltd"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Corp Secure Global CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp Secure Security CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(privkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=180))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("smtp.corp-secure.com"),
                x509.DNSName("mail.corp-secure.com"),
                x509.DNSName("mx1.corp-secure.com"),
            ]),
            critical=False,
        )
        .sign(privkey, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # 2. Build packets
    client_ip = "192.168.10.45"
    server_ip = "198.51.100.25"
    c_port = 52140
    s_port = 587

    pkts = []
    # TCP 3-way handshake
    pkts.append(IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="S", seq=100))
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="SA", seq=500, ack=101))
    pkts.append(IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="A", seq=101, ack=501))

    # SMTP Plaintext phase
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=501, ack=101) / Raw(load=b"220 smtp.corp-secure.com ESMTP Postfix\r\n"))
    pkts.append(IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="PA", seq=101, ack=541) / Raw(load=b"EHLO mail-client.internal\r\n"))
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=541, ack=128) / Raw(load=b"250-smtp.corp-secure.com\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n"))
    pkts.append(IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="PA", seq=128, ack=635) / Raw(load=b"STARTTLS\r\n"))
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=635, ack=138) / Raw(load=b"220 2.0.0 Ready to start TLS\r\n"))

    # TLS Phase - ClientHello
    # SNI extension
    sni_host = b"smtp.corp-secure.com"
    sni_ext = (
        b"\x00\x00"
        + (len(sni_host) + 5).to_bytes(2, "big")
        + (len(sni_host) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(sni_host).to_bytes(2, "big")
        + sni_host
    )
    exts = len(sni_ext).to_bytes(2, "big") + sni_ext
    ciphers = b"\x00\x06\xc0\x2f\xc0\x30\x00\x35"  # ECDHE-RSA-AES128-GCM, ECDHE-RSA-AES256-GCM, RSA-AES256-SHA

    ch_body = b"\x03\x03" + b"\x12" * 32 + b"\x00" + ciphers + b"\x01\x00" + exts
    ch_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    ch_record = b"\x16\x03\x03" + len(ch_msg).to_bytes(2, "big") + ch_msg
    pkts.append(IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="PA", seq=138, ack=665) / Raw(load=ch_record))

    # TLS Phase - ServerHello (Negotiating 0xC02F: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> PFS!)
    sh_body = b"\x03\x03" + b"\x34" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00" + b"\x00\x00"
    sh_msg = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    sh_record = b"\x16\x03\x03" + len(sh_msg).to_bytes(2, "big") + sh_msg
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=665, ack=138 + len(ch_record)) / Raw(load=sh_record))

    # TLS Phase - Certificate Message
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    cert_body = len(cert_entry).to_bytes(3, "big") + cert_entry
    cert_msg = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    cert_record = b"\x16\x03\x03" + len(cert_msg).to_bytes(2, "big") + cert_msg
    pkts.append(IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=665 + len(sh_record), ack=138 + len(ch_record)) / Raw(load=cert_record))

    out_path = Path(output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    print(f"[+] Created sample capture at: {out_path} ({len(pkts)} packets)")
    return str(out_path)


if __name__ == "__main__":
    generate_sample_smtp_tls_pcap("sample_captures/smtp_starttls_pfs_sample.pcap")
