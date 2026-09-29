import time
import requests

def test_ml_pipeline():
    # 1. Test Clean Capture
    print("[1] Testing Clean PCAP (smtp_starttls_pfs_sample.pcap)...")
    url = "http://localhost:8000/api/pcap/upload?auto_process=true"
    pcap_path = "sample_captures/smtp_starttls_pfs_sample.pcap"
    
    with open(pcap_path, "rb") as f:
        r = requests.post(url, files={"file": ("smtp_starttls_pfs_sample.pcap", f, "application/octet-stream")})
    
    job_id_clean = r.json()["job_id"]
    for _ in range(15):
        time.sleep(0.5)
        st_data = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id_clean}").json()
        if st_data.get("status") in ("COMPLETED", "FAILED"):
            break

    print(f"    Clean Job Status: {st_data['status']}")
    print(f"    Risk Score (Deterministic): {st_data['risk_score']}/100")
    print(f"    AI Risk Score: {st_data.get('ml_risk_score')}/100")
    print(f"    ML Anomaly Count: {st_data.get('ml_anomaly_count')}")

    insights_clean = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id_clean}/ai-insights").json()
    print(f"    AI Verdict: {insights_clean['ai_verdict']}")
    print(f"    Anomalies Flagged: {insights_clean['anomalous_sessions_count']}/{insights_clean['total_sessions']}")

    # 2. Test Vulnerable Capture
    print("\n[2] Testing Vulnerable PCAP (smtp_vulnerable_sample.pcap)...")
    pcap_path_vuln = "sample_captures/smtp_vulnerable_sample.pcap"
    with open(pcap_path_vuln, "rb") as f:
        r = requests.post(url, files={"file": ("smtp_vulnerable_sample.pcap", f, "application/octet-stream")})
    
    job_id_vuln = r.json()["job_id"]
    for _ in range(15):
        time.sleep(0.5)
        st_data = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id_vuln}").json()
        if st_data.get("status") in ("COMPLETED", "FAILED"):
            break

    print(f"    Vulnerable Job Status: {st_data['status']}")
    print(f"    Risk Score (Deterministic): {st_data['risk_score']}/100")
    print(f"    AI Risk Score: {st_data.get('ml_risk_score')}/100")
    print(f"    ML Anomaly Count: {st_data.get('ml_anomaly_count')}")

    insights_vuln = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id_vuln}/ai-insights").json()
    print(f"    AI Verdict: {insights_vuln['ai_verdict']}")
    print(f"    Anomalies Flagged: {insights_vuln['anomalous_sessions_count']}/{insights_vuln['total_sessions']}")
    print(f"    Primary Vectors: {insights_vuln['primary_anomaly_vectors']}")

    for s in insights_vuln["anomalous_streams"]:
        print(f"\n    Stream #{s['stream_index']} ({s['protocol']} {s['client_ip']} -> {s['server_ip']}:{s['server_port']}):")
        print(f"      Anomaly Score: {s['anomaly_score']:.1f}%")
        print(f"      Reasons:")
        for reason in s["anomaly_reasons"]:
            print(f"        - {reason}")

if __name__ == "__main__":
    test_ml_pipeline()
