import time
import requests

def test_vulnerable_flow():
    url = "http://localhost:8000/api/pcap/upload?auto_process=true"
    pcap_path = "sample_captures/smtp_vulnerable_sample.pcap"
    
    with open(pcap_path, "rb") as f:
        r = requests.post(url, files={"file": ("smtp_vulnerable_sample.pcap", f, "application/octet-stream")})
    
    print("[1] Upload response:", r.status_code)
    data = r.json()
    job_id = data["job_id"]
    print(f"    Job ID: {job_id}")

    # Wait for processing
    for _ in range(10):
        time.sleep(0.5)
        st_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}")
        st_data = st_r.json()
        if st_data.get("status") in ("COMPLETED", "FAILED"):
            break

    print(f"[2] Processing status: {st_data['status']}")
    print(f"    Total Packets: {st_data['total_packets']}")
    print(f"    Total Sessions: {st_data['total_sessions']}")

    # Module 4: Fetch Security Findings and Executive Risk Summary
    findings_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/findings")
    findings = findings_r.json()
    print(f"\n[3] Module 4: Security Vulnerability Findings ({len(findings)} identified):")
    for f in findings:
        print(f"      [{f['severity']}] ({f['category']}) {f['title']}")
        print(f"         Affected: {f['affected_entity']}")
        print(f"         Remediation: {f['remediation'][:90]}...")

    risk_r = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/risk-summary")
    risk = risk_r.json()
    print(f"\n[4] Module 4: Executive Risk Posture Summary:")
    print(f"      Risk Score: {risk['risk_score']}/100")
    print(f"      Grade: {risk['risk_grade']} ({risk['risk_level']})")
    print(f"      Breakdown: {risk['critical_count']} Critical, {risk['high_count']} High, {risk['medium_count']} Medium, {risk['low_count']} Low, {risk['info_count']} Info")

if __name__ == "__main__":
    test_vulnerable_flow()
