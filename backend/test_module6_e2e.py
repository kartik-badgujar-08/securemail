import time
import requests
from pathlib import Path

def test_module6_e2e():
    print("[*] Uploading sample capture for Module 6 report generation...")
    url = "http://localhost:8000/api/pcap/upload?auto_process=true"
    pcap_path = "sample_captures/smtp_vulnerable_sample.pcap"

    with open(pcap_path, "rb") as f:
        r = requests.post(url, files={"file": ("smtp_vulnerable_sample.pcap", f, "application/octet-stream")})

    assert r.status_code == 201, f"Upload failed: {r.status_code}"
    job_id = r.json()["job_id"]
    print(f"    Job ID: {job_id}")

    # Wait for pipeline completion
    for _ in range(20):
        time.sleep(0.5)
        st = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}").json()
        if st.get("status") in ("COMPLETED", "FAILED"):
            break

    print(f"    Processing status: {st['status']}")
    assert st["status"] == "COMPLETED"

    # 1. Test Structured JSON Export
    print("\n[1] Testing Structured JSON Report Export...")
    r_json = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/report/json")
    assert r_json.status_code == 200
    assert "attachment; filename=" in r_json.headers.get("content-disposition", "")
    json_data = r_json.json()
    print("    [+] Metadata:", json_data["metadata"]["filename"], f"({json_data['metadata']['total_sessions']} sessions)")
    print("    [+] Executive Summary:", json_data["executive_summary"])
    print("    [+] Vulnerabilities Count:", len(json_data["vulnerabilities"]))
    print("    [+] AI Anomalies Count:", len(json_data["ai_anomalies"]))

    # 2. Test Printable HTML Report
    print("\n[2] Testing Printable HTML Report Export...")
    r_html = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/report/html")
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers.get("content-type", "")
    assert "MailSec TLS Executive Security Audit" in r_html.text
    print("    [+] HTML report generated successfully (length:", len(r_html.text), "chars)")

    # 3. Test Native Binary PDF Report
    print("\n[3] Testing Native Binary PDF Report Export...")
    r_pdf = requests.get(f"http://localhost:8000/api/pcap/jobs/{job_id}/report/pdf")
    assert r_pdf.status_code == 200
    assert r_pdf.headers.get("content-type") == "application/pdf"
    assert "attachment; filename=" in r_pdf.headers.get("content-disposition", "")
    assert r_pdf.content.startswith(b"%PDF-")
    print(f"    [+] PDF report generated successfully ({len(r_pdf.content)} bytes, starts with %PDF-)")

    # Save PDF to disk for manual inspection
    out_pdf_path = Path("sample_captures/MailSec_Audit_Report.pdf")
    with open(out_pdf_path, "wb") as f:
        f.write(r_pdf.content)
    print(f"    [+] Saved audit report to disk: {out_pdf_path}")

    print("\n[OK] Module 6 E2E Verification complete: All 3 export formats (JSON, HTML, PDF) verified!")

if __name__ == "__main__":
    test_module6_e2e()
