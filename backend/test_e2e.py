import time
import requests

def test_pipeline():
    url = "http://localhost:8000/api/pcap/upload?auto_process=true"
    pcap_path = "sample_captures/smtp_starttls_pfs_sample.pcap"
    
    with open(pcap_path, "rb") as f:
        r = requests.post(url, files={"file": ("smtp_starttls_pfs_sample.pcap", f, "application/octet-stream")})
    
    print("[1] Upload response:", r.status_code)
    data = r.json()
    job_id = data["job_id"]
    print(f"    Job ID: {job_id}")
    print(f"    SHA-256: {data['sha256_hash'][:16]}...")
    print(f"    Status: {data['status']}")

    # Wait for processing
    for _ in range(10):
        time.sleep(0.5)
        st_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}")
        st_data = st_r.json()
        print("    Poll:", st_r.status_code, st_data)
        if st_data.get("status") in ("COMPLETED", "FAILED"):
            break

    print(f"[2] Processing finished with status: {st_data['status']}")
    print(f"    Total Packets: {st_data['total_packets']}")
    print(f"    Total Sessions: {st_data['total_sessions']}")

    # Fetch reconstructed streams
    streams_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/streams")
    streams = streams_r.json()
    print(f"[3] Reconstructed Sessions: {len(streams)}")
    
    for s in streams:
        print(f"    Stream #{s['stream_index']}: {s['protocol']}")
        print(f"      Endpoints: {s['client_ip']}:{s['client_port']} -> {s['server_ip']}:{s['server_port']}")
        print(f"      STARTTLS: {s['has_starttls']} (Packet #{s.get('starttls_packet_index')})")
        print(f"      TLS Encrypted: {s['is_tls_encrypted']} ({s.get('tls_version')})")
        print(f"      Cipher Suite: {s.get('cipher_suite')}")
        print(f"      PFS: {s.get('has_pfs')} ({s.get('key_exchange')})")

        # Fetch handshake details
        hs_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/streams/{s['id']}/handshake")
        hs = hs_r.json()
        print(f"[4] Deep TLS Handshake Details:")
        print(f"      Client Offered Ciphers Count: {len(hs.get('client_cipher_suites', []))}")
        print(f"      Server Negotiated PFS: {hs.get('has_pfs')}")
        print(f"      Server Key Exchange: {hs.get('key_exchange')}")
        print(f"      Extracted Certificates: {len(hs.get('certificates', []))}")
        
        for c in hs.get("certificates", []):
            print(f"        -> Subject CN: {c['subject_cn']}")
            print(f"           Issuer CN: {c['issuer_cn']}")
            print(f"           Key: {c['public_key_algorithm']} {c['public_key_bits']}-bit (Weak: {c['is_weak_key']})")
            print(f"           Sig Hash: {c['signature_hash']} (Weak: {c['is_weak_hash']})")
            print(f"           Self-Signed: {c['is_self_signed']}")
            print(f"           Days to Expiry: {c['days_until_expiry']} (Expired: {c['is_expired']})")
            print(f"           SANs: {c['san_dns_names']}")

    # Module 4: Fetch Security Findings and Executive Risk Summary
    findings_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/findings")
    findings = findings_r.json()
    print(f"\n[5] Module 4: Security Vulnerability Findings ({len(findings)} found):")
    for f in findings:
        print(f"      [{f['severity']}] ({f['category']}) {f['title']}")
        print(f"         Affected: {f['affected_entity']}")
        print(f"         Remediation: {f['remediation'][:80]}...")

    risk_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/risk-summary")
    risk = risk_r.json()
    print(f"\n[6] Module 4: Executive Risk Posture Summary:")
    print(f"      Risk Score: {risk['risk_score']}/100")
    print(f"      Grade: {risk['risk_grade']} ({risk['risk_level']})")
    print(f"      Breakdown: {risk['critical_count']} Critical, {risk['high_count']} High, {risk['medium_count']} Medium, {risk['low_count']} Low, {risk['info_count']} Info")

if __name__ == "__main__":
    test_pipeline()
