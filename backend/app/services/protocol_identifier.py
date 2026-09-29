import re
from typing import Optional, Tuple, Dict, Any

# Standard Ports
SMTP_PORTS = {25, 587, 465, 2525}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}

# Regex Patterns for Plaintext Signatures
SMTP_BANNER_REGEX = re.compile(rb"^220[ -]", re.IGNORECASE)
SMTP_RESPONSE_REGEX = re.compile(rb"^(?:220|250|354|421|450|451|452|500|501|502|503|504|550|551|552|553|554)[ -]", re.IGNORECASE)
SMTP_COMMAND_REGEX = re.compile(rb"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:|STARTTLS|QUIT|DATA|RSET|VRFY|NOOP)", re.IGNORECASE)
SMTP_STARTTLS_CMD = re.compile(rb"^STARTTLS\r?\n?", re.IGNORECASE)
SMTP_STARTTLS_OK = re.compile(rb"^220[ -].*?(?:ready|tls|start)", re.IGNORECASE)

IMAP_BANNER_REGEX = re.compile(rb"^\*\s+(?:OK|BYE|PREAUTH|CAPABILITY)", re.IGNORECASE)
IMAP_COMMAND_REGEX = re.compile(rb"^(?:\*|[a-z0-9]+)\s+(?:CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|SELECT|LOGOUT|NOOP|OK|NO|BAD)", re.IGNORECASE)
IMAP_STARTTLS_CMD = re.compile(rb"^[a-z0-9]+\s+STARTTLS\r?\n?", re.IGNORECASE)
IMAP_STARTTLS_OK = re.compile(rb"^[a-z0-9]+\s+OK.*?(?:begin|tls|start)", re.IGNORECASE)

POP3_BANNER_REGEX = re.compile(rb"^\+OK\s+.*?(?:pop|ready|server)", re.IGNORECASE)
POP3_COMMAND_REGEX = re.compile(rb"^(?:USER|PASS|STLS|STAT|LIST|RETR|DELE|QUIT|CAPA)", re.IGNORECASE)
POP3_STLS_CMD = re.compile(rb"^STLS\r?\n?", re.IGNORECASE)
POP3_STLS_OK = re.compile(rb"^\+OK.*?(?:begin|tls|start)", re.IGNORECASE)


class ProtocolIdentifier:
    @staticmethod
    def identify_protocol_by_port(src_port: int, dst_port: int) -> str:
        """Determines expected protocol from standard port assignments."""
        ports = {src_port, dst_port}
        if ports.intersection(SMTP_PORTS):
            return "SMTP"
        if ports.intersection(IMAP_PORTS):
            return "IMAP"
        if ports.intersection(POP3_PORTS):
            return "POP3"
        return "UNKNOWN"

    @staticmethod
    def inspect_payload_signature(payload: bytes, default_protocol: str = "UNKNOWN") -> Tuple[str, Dict[str, Any]]:
        """
        Inspects application payload bytes to detect protocol and extract protocol-specific metadata.
        Returns (detected_protocol, protocol_info_dict).
        """
        if not payload:
            return default_protocol, {}

        info: Dict[str, Any] = {}
        sample = payload[:256]

        # 1. SMTP Detection
        if (
            SMTP_BANNER_REGEX.search(sample)
            or SMTP_RESPONSE_REGEX.search(sample)
            or SMTP_COMMAND_REGEX.search(sample)
            or default_protocol == "SMTP"
        ):
            try:
                text = sample.decode("utf-8", errors="replace").strip()
                info["sample_text"] = text
                if SMTP_STARTTLS_CMD.search(payload):
                    info["command"] = "STARTTLS"
                elif SMTP_STARTTLS_OK.search(payload):
                    info["response"] = "220_READY_FOR_TLS"
                elif text.startswith("220"):
                    info["banner"] = text
                elif any(text.upper().startswith(cmd) for cmd in ["EHLO", "HELO", "MAIL FROM", "RCPT TO"]):
                    info["command"] = text.splitlines()[0]
                return "SMTP", info
            except Exception:
                pass

        # 2. IMAP Detection
        if IMAP_BANNER_REGEX.search(sample) or IMAP_COMMAND_REGEX.search(sample) or default_protocol == "IMAP":
            try:
                text = sample.decode("utf-8", errors="replace").strip()
                info["sample_text"] = text
                if IMAP_STARTTLS_CMD.search(payload):
                    info["command"] = "STARTTLS"
                elif IMAP_STARTTLS_OK.search(payload):
                    info["response"] = "OK_BEGIN_TLS"
                elif text.startswith("* OK"):
                    info["banner"] = text
                return "IMAP", info
            except Exception:
                pass

        # 3. POP3 Detection
        if POP3_BANNER_REGEX.search(sample) or POP3_COMMAND_REGEX.search(sample) or default_protocol == "POP3":
            try:
                text = sample.decode("utf-8", errors="replace").strip()
                info["sample_text"] = text
                if POP3_STLS_CMD.search(payload):
                    info["command"] = "STLS"
                elif POP3_STLS_OK.search(payload):
                    info["response"] = "OK_BEGIN_TLS"
                elif text.startswith("+OK"):
                    info["banner"] = text
                return "POP3", info
            except Exception:
                pass

        return default_protocol, info

    @classmethod
    def detect_stream_protocol(
        cls, client_port: int, server_port: int, payloads: list[bytes]
    ) -> Tuple[str, bool, Optional[int]]:
        """
        Analyzes full stream payloads and ports to determine:
        (protocol, has_starttls, starttls_packet_index)
        """
        protocol = cls.identify_protocol_by_port(client_port, server_port)
        has_starttls = False
        starttls_packet_index = None

        saw_starttls_command = False

        for idx, payload in enumerate(payloads):
            if not payload:
                continue

            detected, info = cls.inspect_payload_signature(payload, default_protocol=protocol)
            if detected != "UNKNOWN" and protocol == "UNKNOWN":
                protocol = detected

            # STARTTLS state tracking
            if info.get("command") in ("STARTTLS", "STLS"):
                saw_starttls_command = True

            if saw_starttls_command and info.get("response") in ("220_READY_FOR_TLS", "OK_BEGIN_TLS"):
                has_starttls = True
                starttls_packet_index = idx
                break

        return protocol, has_starttls, starttls_packet_index
