import hashlib
from pathlib import Path
from typing import Tuple, Optional
from fastapi import HTTPException, status
from app.config import settings

# Supported capture magic bytes (4-byte prefixes)
PCAP_MAGIC_BYTES = {
    b"\xa1\xb2\xc3\xd4": "pcap (microsecond, standard)",
    b"\xd4\xc3\xb2\xa1": "pcap (microsecond, byte-swapped)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, standard)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, byte-swapped)",
}

PCAPNG_MAGIC_BYTE = b"\x0a\x0d\x0d\x0a"  # Section Header Block (SHB)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


class PCAPValidationError(HTTPException):
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class PCAPValidator:
    @staticmethod
    def validate_filename_extension(filename: str) -> str:
        """Validates that the file has an allowed capture extension."""
        path = Path(filename)
        ext = path.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            allowed = ", ".join(ALLOWED_EXTENSIONS)
            raise PCAPValidationError(
                f"Invalid file extension '{ext}'. Only capture files ({allowed}) are accepted."
            )
        return ext

    @staticmethod
    def validate_magic_bytes(header: bytes) -> str:
        """
        Validates capture file magic bytes for PCAP and PCAPNG formats.
        Returns the detected capture format name.
        """
        if len(header) < 4:
            raise PCAPValidationError("File is truncated or empty; cannot read capture header.")

        prefix4 = header[:4]
        if prefix4 == PCAPNG_MAGIC_BYTE:
            return "PCAPNG"
        elif prefix4 in PCAP_MAGIC_BYTES:
            return f"PCAP ({PCAP_MAGIC_BYTES[prefix4]})"
        else:
            hex_received = prefix4.hex()
            raise PCAPValidationError(
                f"Corrupt or invalid capture header. Expected PCAP or PCAPNG magic bytes, got 0x{hex_received}."
            )

    @staticmethod
    def validate_file_size(size_bytes: int) -> None:
        """Validates that the file size is non-empty and does not exceed configured limits."""
        if size_bytes == 0:
            raise PCAPValidationError("The uploaded file is empty (0 bytes).")
        
        max_bytes = settings.max_upload_size_bytes
        if size_bytes > max_bytes:
            max_mb = settings.MAX_UPLOAD_SIZE_MB
            raise PCAPValidationError(
                f"File size exceeds the {max_mb} MB limit (received {size_bytes / (1024*1024):.2f} MB).",
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

    @classmethod
    def compute_sha256_and_validate(cls, file_path: Path) -> Tuple[str, int, str]:
        """
        Computes SHA-256 hash while validating size and magic bytes on disk.
        Returns (sha256_hash, file_size_bytes, capture_format).
        """
        if not file_path.is_file():
            raise PCAPValidationError(f"File not found at {file_path}")

        file_size = file_path.stat().st_size
        cls.validate_file_size(file_size)

        sha256 = hashlib.sha256()
        header = b""

        with open(file_path, "rb") as f:
            chunk = f.read(65536)
            if chunk:
                header = chunk[:4]
                sha256.update(chunk)
            while chunk := f.read(65536):
                sha256.update(chunk)

        capture_format = cls.validate_magic_bytes(header)
        return sha256.hexdigest(), file_size, capture_format
