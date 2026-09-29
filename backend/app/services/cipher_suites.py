from typing import Dict, Any, Optional

# Security Categories
SEC_SECURE = "SECURE"
SEC_ACCEPTABLE = "ACCEPTABLE"
SEC_WEAK = "WEAK"
SEC_INSECURE = "INSECURE"

# Key Exchange Categories
KX_ECDHE = "ECDHE"
KX_DHE = "DHE"
KX_RSA = "RSA"
KX_TLS13 = "TLS1.3_EPHEMERAL"
KX_UNKNOWN = "UNKNOWN"

# IANA Cipher Suites Dictionary
# Format: hex_code -> { name, kx, bulk, hash, pfs, security }
CIPHER_SUITES_DB: Dict[int, Dict[str, Any]] = {
    # TLS 1.3 Ciphers (RFC 8446) - All enforce Perfect Forward Secrecy (PFS)
    0x1301: {
        "name": "TLS_AES_128_GCM_SHA256",
        "kx": KX_TLS13,
        "bulk": "AES_128_GCM",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x1302: {
        "name": "TLS_AES_256_GCM_SHA384",
        "kx": KX_TLS13,
        "bulk": "AES_256_GCM",
        "hash": "SHA384",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x1303: {
        "name": "TLS_CHACHA20_POLY1305_SHA256",
        "kx": KX_TLS13,
        "bulk": "CHACHA20_POLY1305",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x1304: {
        "name": "TLS_AES_128_CCM_SHA256",
        "kx": KX_TLS13,
        "bulk": "AES_128_CCM",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x1305: {
        "name": "TLS_AES_128_CCM_8_SHA256",
        "kx": KX_TLS13,
        "bulk": "AES_128_CCM_8",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },

    # Modern TLS 1.2 ECDHE with AEAD (PFS = True)
    0xC02B: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "kx": KX_ECDHE,
        "bulk": "AES_128_GCM",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0xC02C: {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "kx": KX_ECDHE,
        "bulk": "AES_256_GCM",
        "hash": "SHA384",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0xC02F: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "kx": KX_ECDHE,
        "bulk": "AES_128_GCM",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0xC030: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "kx": KX_ECDHE,
        "bulk": "AES_256_GCM",
        "hash": "SHA384",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0xCCA8: {
        "name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "kx": KX_ECDHE,
        "bulk": "CHACHA20_POLY1305",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0xCCA9: {
        "name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "kx": KX_ECDHE,
        "bulk": "CHACHA20_POLY1305",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x9E: {
        "name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "kx": KX_DHE,
        "bulk": "AES_128_GCM",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_SECURE,
    },
    0x9F: {
        "name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "kx": KX_DHE,
        "bulk": "AES_256_GCM",
        "hash": "SHA384",
        "pfs": True,
        "security": SEC_SECURE,
    },

    # TLS 1.2 ECDHE / DHE with CBC (PFS = True, but CBC is Acceptable / Weak due to padding oracle risk)
    0xC013: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "kx": KX_ECDHE,
        "bulk": "AES_128_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },
    0xC014: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "kx": KX_ECDHE,
        "bulk": "AES_256_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },
    0xC027: {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "kx": KX_ECDHE,
        "bulk": "AES_128_CBC",
        "hash": "SHA256",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },
    0xC028: {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "kx": KX_ECDHE,
        "bulk": "AES_256_CBC",
        "hash": "SHA384",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },
    0x33: {
        "name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "kx": KX_DHE,
        "bulk": "AES_128_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },
    0x39: {
        "name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "kx": KX_DHE,
        "bulk": "AES_256_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_ACCEPTABLE,
    },

    # Static RSA Key Exchange (NO Forward Secrecy / PFS = False)
    0x9C: {
        "name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "kx": KX_RSA,
        "bulk": "AES_128_GCM",
        "hash": "SHA256",
        "pfs": False,
        "security": SEC_WEAK,
    },
    0x9D: {
        "name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "kx": KX_RSA,
        "bulk": "AES_256_GCM",
        "hash": "SHA384",
        "pfs": False,
        "security": SEC_WEAK,
    },
    0x2F: {
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "kx": KX_RSA,
        "bulk": "AES_128_CBC",
        "hash": "SHA1",
        "pfs": False,
        "security": SEC_WEAK,
    },
    0x35: {
        "name": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "kx": KX_RSA,
        "bulk": "AES_256_CBC",
        "hash": "SHA1",
        "pfs": False,
        "security": SEC_WEAK,
    },
    0x3C: {
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "kx": KX_RSA,
        "bulk": "AES_128_CBC",
        "hash": "SHA256",
        "pfs": False,
        "security": SEC_WEAK,
    },
    0x3D: {
        "name": "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "kx": KX_RSA,
        "bulk": "AES_256_CBC",
        "hash": "SHA256",
        "pfs": False,
        "security": SEC_WEAK,
    },

    # Deprecated / Broken Legacy Ciphers (3DES, RC4, DES, NULL)
    0x0A: {
        "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "kx": KX_RSA,
        "bulk": "3DES_EDE_CBC",
        "hash": "SHA1",
        "pfs": False,
        "security": SEC_INSECURE,
    },
    0xC012: {
        "name": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "kx": KX_ECDHE,
        "bulk": "3DES_EDE_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_INSECURE,
    },
    0x16: {
        "name": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "kx": KX_DHE,
        "bulk": "3DES_EDE_CBC",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_INSECURE,
    },
    0x04: {
        "name": "TLS_RSA_WITH_RC4_128_MD5",
        "kx": KX_RSA,
        "bulk": "RC4_128",
        "hash": "MD5",
        "pfs": False,
        "security": SEC_INSECURE,
    },
    0x05: {
        "name": "TLS_RSA_WITH_RC4_128_SHA",
        "kx": KX_RSA,
        "bulk": "RC4_128",
        "hash": "SHA1",
        "pfs": False,
        "security": SEC_INSECURE,
    },
    0xC011: {
        "name": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "kx": KX_ECDHE,
        "bulk": "RC4_128",
        "hash": "SHA1",
        "pfs": True,
        "security": SEC_INSECURE,
    },
    0x09: {
        "name": "TLS_RSA_WITH_DES_CBC_SHA",
        "kx": KX_RSA,
        "bulk": "DES_CBC",
        "hash": "SHA1",
        "pfs": False,
        "security": SEC_INSECURE,
    },
}


class CipherSuiteHelper:
    @staticmethod
    def get_info(cipher_id: int) -> Dict[str, Any]:
        """Looks up cipher metadata by integer/hex code."""
        if cipher_id in CIPHER_SUITES_DB:
            info = CIPHER_SUITES_DB[cipher_id].copy()
            info["hex_code"] = f"0x{cipher_id:04x}"
            return info

        # Heuristic lookup if not explicitly in table
        hex_str = f"0x{cipher_id:04x}"
        return {
            "name": f"UNKNOWN_CIPHER_{hex_str}",
            "hex_code": hex_str,
            "kx": KX_UNKNOWN,
            "bulk": "UNKNOWN",
            "hash": "UNKNOWN",
            "pfs": False,
            "security": SEC_WEAK,
        }

    @classmethod
    def analyze_cipher_name(cls, name: str) -> Dict[str, Any]:
        """Infers security and PFS attributes from a cipher suite name."""
        name_upper = name.upper()
        pfs = "ECDHE" in name_upper or "DHE" in name_upper or name_upper.startswith("TLS_AES_") or name_upper.startswith("TLS_CHACHA20_")

        kx = KX_RSA
        if "ECDHE" in name_upper:
            kx = KX_ECDHE
        elif "DHE" in name_upper:
            kx = KX_DHE
        elif name_upper.startswith("TLS_AES_") or name_upper.startswith("TLS_CHACHA20_"):
            kx = KX_TLS13

        # Check for bad ciphers
        if any(bad in name_upper for bad in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]):
            sec = SEC_INSECURE
        elif not pfs:
            sec = SEC_WEAK
        elif "CBC" in name_upper:
            sec = SEC_ACCEPTABLE
        else:
            sec = SEC_SECURE

        return {
            "name": name,
            "kx": kx,
            "pfs": pfs,
            "security": sec,
        }
