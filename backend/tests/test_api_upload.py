import io
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from app.main import app
from app.database import get_db
from app.models.analysis_job import AnalysisJob

client = TestClient(app)


def test_upload_invalid_extension():
    response = client.post(
        "/api/pcap/upload",
        files={"file": ("capture.txt", b"plain text", "text/plain")},
    )
    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


def test_upload_corrupt_magic_bytes():
    response = client.post(
        "/api/pcap/upload",
        files={"file": ("corrupt.pcap", b"\x00\x01\x02\x03\x04\x05", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Corrupt or invalid capture header" in response.json()["detail"]


def test_upload_valid_pcap_creates_queued_job():
    # Microsecond PCAP header
    valid_pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"

    mock_db = MagicMock()
    # No existing duplicate
    mock_db.query.return_value.filter.return_value.first.return_value = None

    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.post(
            "/api/pcap/upload?auto_process=false",
            files={"file": ("valid_sample.pcap", valid_pcap_header, "application/octet-stream")},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["filename"] == "valid_sample.pcap"
        assert data["status"] == "QUEUED"
        assert data["is_duplicate"] is False
        assert len(data["sha256_hash"]) == 64
        assert "Valid PCAP" in data["message"]
        assert mock_db.add.called
        assert mock_db.commit.called
    finally:
        app.dependency_overrides.clear()


def test_upload_duplicate_pcap_option_b():
    valid_pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"

    mock_existing_job = MagicMock()
    mock_existing_job.id = "job-uuid-1234"

    mock_db = MagicMock()
    # Simulate existing duplicate found
    mock_db.query.return_value.filter.return_value.first.return_value = mock_existing_job

    def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.post(
            "/api/pcap/upload?auto_process=false",
            files={"file": ("second_upload.pcap", valid_pcap_header, "application/octet-stream")},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["is_duplicate"] is True
        assert "Notice: Capture SHA-256" in data["message"]
        assert "Option B" in data["message"]
        assert data["status"] == "QUEUED"
    finally:
        app.dependency_overrides.clear()
