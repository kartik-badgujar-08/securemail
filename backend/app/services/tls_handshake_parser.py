import logging
from typing import Dict, Any, List, Optional, Tuple
from app.services.cipher_suites import CipherSuiteHelper
from app.services.cert_parser import CertificateParser

logger = logging.getLogger(__name__)

# Handshake Types
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CLIENT_KEY_EXCHANGE = 16

# Extension Types
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINTS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

NAMED_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}


class TLSHandshakeParser:
    """Dissects raw TLS handshake messages, parsing ClientHello, ServerHello, and Certificate chains."""

    @classmethod
    def parse_tls_record(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses a TLS record (RFC 5246/8446) from raw TCP payload bytes.
        Returns parsed handshake structure or None if not a valid TLS record.
        """
        if len(data) < 5:
            return None

        content_type = data[0]
        # Only parse Handshake records (0x16)
        if content_type != 0x16:
            return None

        record_version = int.from_bytes(data[1:3], "big")
        record_len = int.from_bytes(data[3:5], "big")

        if len(data) < 5 + min(record_len, 4):
            return None

        # Parse Handshake Message(s) inside this record
        pos = 5
        handshake_messages = []

        while pos + 4 <= len(data):
            msg_type = data[pos]
            msg_len = int.from_bytes(data[pos+1:pos+4], "big")
            msg_payload = data[pos+4 : pos+4+msg_len]
            pos += 4 + msg_len

            if msg_type == HS_CLIENT_HELLO:
                parsed_ch = cls._parse_client_hello(msg_payload)
                handshake_messages.append({"type": "ClientHello", "data": parsed_ch})
            elif msg_type == HS_SERVER_HELLO:
                parsed_sh = cls._parse_server_hello(msg_payload)
                handshake_messages.append({"type": "ServerHello", "data": parsed_sh})
            elif msg_type == HS_CERTIFICATE:
                parsed_certs = cls._parse_certificates(msg_payload)
                handshake_messages.append({"type": "Certificate", "certificates": parsed_certs})

        return {
            "record_version": TLS_VERSIONS.get(record_version, f"0x{record_version:04x}"),
            "messages": handshake_messages,
        }

    @classmethod
    def _parse_client_hello(cls, data: bytes) -> Dict[str, Any]:
        """Dissects ClientHello parameters: version, cipher list, and extensions."""
        if len(data) < 34:
            return {}

        client_version = int.from_bytes(data[0:2], "big")
        random_bytes = data[2:34].hex()
        pos = 34

        # Session ID
        session_id_len = data[pos] if pos < len(data) else 0
        pos += 1 + session_id_len

        # Cipher Suites
        cipher_suites = []
        if pos + 2 <= len(data):
            cs_len = int.from_bytes(data[pos:pos+2], "big")
            pos += 2
            cs_end = pos + cs_len
            while pos + 2 <= cs_end and pos + 2 <= len(data):
                cid = int.from_bytes(data[pos:pos+2], "big")
                cipher_suites.append(CipherSuiteHelper.get_info(cid))
                pos += 2

        # Compression Methods
        if pos < len(data):
            comp_len = data[pos]
            pos += 1 + comp_len

        # Extensions
        extensions = cls._parse_extensions(data[pos:])

        # Check for TLS 1.3 in supported_versions extension
        effective_version = TLS_VERSIONS.get(client_version, f"0x{client_version:04x}")
        if "supported_versions" in extensions:
            if "TLS 1.3" in extensions["supported_versions"]:
                effective_version = "TLS 1.3 (Advertised)"

        return {
            "version": effective_version,
            "random": random_bytes,
            "cipher_suites_count": len(cipher_suites),
            "cipher_suites": cipher_suites,
            "sni": extensions.get("sni"),
            "supported_groups": extensions.get("supported_groups", []),
            "alpn": extensions.get("alpn", []),
            "extensions": extensions,
        }

    @classmethod
    def _parse_server_hello(cls, data: bytes) -> Dict[str, Any]:
        """Dissects ServerHello: negotiated version, cipher suite, and PFS key exchange."""
        if len(data) < 38:
            return {}

        server_version = int.from_bytes(data[0:2], "big")
        random_bytes = data[2:34].hex()
        pos = 34

        session_id_len = data[pos] if pos < len(data) else 0
        pos += 1 + session_id_len

        negotiated_cipher: Dict[str, Any] = {}
        if pos + 2 <= len(data):
            cid = int.from_bytes(data[pos:pos+2], "big")
            negotiated_cipher = CipherSuiteHelper.get_info(cid)
            pos += 2

        # Compression
        pos += 1

        # Extensions
        extensions = cls._parse_extensions(data[pos:])

        # Check for TLS 1.3 downgrade or upgrade via supported_versions
        effective_version = TLS_VERSIONS.get(server_version, f"0x{server_version:04x}")
        if "selected_version" in extensions:
            effective_version = extensions["selected_version"]

        return {
            "version": effective_version,
            "random": random_bytes,
            "cipher_suite": negotiated_cipher,
            "has_pfs": negotiated_cipher.get("pfs", False),
            "key_exchange": negotiated_cipher.get("kx", "UNKNOWN"),
            "security_level": negotiated_cipher.get("security", "WEAK"),
            "extensions": extensions,
        }

    @classmethod
    def _parse_certificates(cls, data: bytes) -> List[Dict[str, Any]]:
        """Extracts X.509 ASN.1 DER certificates from the TLS Certificate message."""
        if len(data) < 3:
            return []

        # Total certificates length (3 bytes)
        total_len = int.from_bytes(data[0:3], "big")
        pos = 3
        certs_end = min(pos + total_len, len(data))

        parsed_chain: List[Dict[str, Any]] = []

        while pos + 3 < certs_end:
            cert_len = int.from_bytes(data[pos:pos+3], "big")
            pos += 3
            if pos + cert_len > len(data):
                break

            der_bytes = data[pos : pos + cert_len]
            pos += cert_len

            try:
                cert_meta = CertificateParser.parse_der_certificate(der_bytes)
                cert_meta["chain_position"] = len(parsed_chain)  # 0 is leaf
                parsed_chain.append(cert_meta)
            except Exception as e:
                logger.warning(f"Failed to parse certificate in chain: {e}")

        return parsed_chain

    @classmethod
    def _parse_extensions(cls, data: bytes) -> Dict[str, Any]:
        """Dissects standard TLS extensions."""
        if len(data) < 2:
            return {}

        ext_total_len = int.from_bytes(data[0:2], "big")
        pos = 2
        ext_end = min(pos + ext_total_len, len(data))
        extensions: Dict[str, Any] = {}

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos+2], "big")
            ext_len = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4
            ext_data = data[pos : pos + ext_len]
            pos += ext_len

            # 1. Server Name Indication (SNI)
            if ext_type == EXT_SERVER_NAME and len(ext_data) >= 5:
                # list_len (2B) -> name_type (1B, 0=host_name) -> name_len (2B) -> name
                try:
                    name_type = ext_data[2]
                    name_len = int.from_bytes(ext_data[3:5], "big")
                    if name_type == 0 and len(ext_data) >= 5 + name_len:
                        extensions["sni"] = ext_data[5:5+name_len].decode("utf-8", "ignore")
                except Exception:
                    pass

            # 2. Supported Groups / Curves
            elif ext_type == EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                groups_len = int.from_bytes(ext_data[0:2], "big")
                groups = []
                g_pos = 2
                while g_pos + 2 <= 2 + groups_len and g_pos + 2 <= len(ext_data):
                    gid = int.from_bytes(ext_data[g_pos:g_pos+2], "big")
                    groups.append(NAMED_GROUPS.get(gid, f"0x{gid:04x}"))
                    g_pos += 2
                extensions["supported_groups"] = groups

            # 3. Supported Versions (TLS 1.3 indicator)
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                if len(ext_data) >= 1:
                    # Could be Client (list) or Server (single version)
                    if len(ext_data) == 2:
                        vid = int.from_bytes(ext_data[0:2], "big")
                        extensions["selected_version"] = TLS_VERSIONS.get(vid, f"0x{vid:04x}")
                    else:
                        v_list_len = ext_data[0]
                        v_pos = 1
                        v_list = []
                        while v_pos + 2 <= 1 + v_list_len and v_pos + 2 <= len(ext_data):
                            vid = int.from_bytes(ext_data[v_pos:v_pos+2], "big")
                            v_list.append(TLS_VERSIONS.get(vid, f"0x{vid:04x}"))
                            v_pos += 2
                        extensions["supported_versions"] = v_list

            # 4. ALPN
            elif ext_type == EXT_ALPN and len(ext_data) >= 2:
                alpn_len = int.from_bytes(ext_data[0:2], "big")
                a_pos = 2
                alpn_list = []
                while a_pos < 2 + alpn_len and a_pos < len(ext_data):
                    proto_len = ext_data[a_pos]
                    a_pos += 1
                    if a_pos + proto_len <= len(ext_data):
                        alpn_list.append(ext_data[a_pos : a_pos+proto_len].decode("utf-8", "ignore"))
                        a_pos += proto_len
                extensions["alpn"] = alpn_list

        return extensions
