import pytest
import tempfile
from pathlib import Path
from fastapi import HTTPException
from app.services.pcap_validator import (
    PCAPValidator,
    PCAPValidationError,
    PCAP_MAGIC_BYTES,
    PCAPNG_MAGIC_BYTE,
)


def test_extension_validation():
    assert PCAPValidator.validate_filename_extension("capture.pcap") == ".pcap"
    assert PCAPValidator.validate_filename_extension("capture.PCAPNG") == ".pcapng"
    assert PCAPValidator.validate_filename_extension("test.cap") == ".cap"

    with pytest.raises(PCAPValidationError) as exc:
        PCAPValidator.validate_filename_extension("malicious.exe")
    assert "Invalid file extension" in str(exc.value.detail)


def test_magic_bytes_pcap():
    for magic in PCAP_MAGIC_BYTES.keys():
        fmt = PCAPValidator.validate_magic_bytes(magic + b"\x00" * 20)
        assert "PCAP" in fmt


def test_magic_bytes_pcapng():
    fmt = PCAPValidator.validate_magic_bytes(PCAPNG_MAGIC_BYTE + b"\x00" * 20)
    assert fmt == "PCAPNG"


def test_magic_bytes_corrupt():
    with pytest.raises(PCAPValidationError) as exc:
        PCAPValidator.validate_magic_bytes(b"\x00\x00\x00\x00")
    assert "Corrupt or invalid capture header" in str(exc.value.detail)


def test_compute_sha256_and_validate():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        # Write valid microsecond PCAP magic bytes + dummy global header
        tmp.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")
        tmp_path = Path(tmp.name)

    try:
        sha256_hash, file_size, fmt = PCAPValidator.compute_sha256_and_validate(tmp_path)
        assert len(sha256_hash) == 64
        assert file_size == 24
        assert "PCAP" in fmt
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
