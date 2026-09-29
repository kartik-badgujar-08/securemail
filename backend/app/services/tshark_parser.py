import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from app.config import settings

logger = logging.getLogger(__name__)


class TSharkParser:
    """Dissects PCAP/PCAPNG captures using TShark's JSON export functionality."""

    @classmethod
    def get_tshark_binary(cls) -> Optional[str]:
        """Locates tshark executable in configured path, system PATH, or standard installation paths."""
        if settings.TSHARK_PATH and os.path.isfile(settings.TSHARK_PATH):
            return settings.TSHARK_PATH

        which_path = shutil.which("tshark")
        if which_path:
            return which_path

        standard_windows_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for path in standard_windows_paths:
            if os.path.isfile(path):
                return path

        return None

    @classmethod
    def is_available(cls) -> bool:
        return cls.get_tshark_binary() is not None

    @classmethod
    def parse_pcap(cls, pcap_path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Executes TShark on the PCAP file and returns:
        (extracted_packets, reconstructed_streams)
        """
        tshark_bin = cls.get_tshark_binary()
        if not tshark_bin:
            raise RuntimeError("TShark binary not found on the system.")

        cmd = [
            tshark_bin,
            "-r", str(pcap_path),
            "-T", "json",
            "-o", "tcp.desegment_tcp_streams:TRUE",
            "-o", "tls.desegment_ssl_records:TRUE",
        ]

        logger.info(f"Running TShark: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=180
            )
            raw_packets = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("TShark execution timed out while analyzing capture.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"TShark error (code {e.returncode}): {e.stderr}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse TShark JSON output: {e}")

        packets: List[Dict[str, Any]] = []
        streams_map: Dict[int, Dict[str, Any]] = {}

        for idx, item in enumerate(raw_packets, start=1):
            source = item.get("_source", {})
            layers = source.get("layers", {})

            # Frame info
            frame = layers.get("frame", {})
            timestamp = float(frame.get("frame.time_epoch", 0.0))
            frame_len = int(frame.get("frame.len", 0))

            # IP info
            ip = layers.get("ip", {}) or layers.get("ipv6", {})
            src_ip = ip.get("ip.src", ip.get("ipv6.src", "0.0.0.0"))
            dst_ip = ip.get("ip.dst", ip.get("ipv6.dst", "0.0.0.0"))

            # TCP info
            tcp = layers.get("tcp", {})
            src_port = int(tcp.get("tcp.srcport", 0)) if tcp.get("tcp.srcport") else None
            dst_port = int(tcp.get("tcp.dstport", 0)) if tcp.get("tcp.dstport") else None
            stream_idx = int(tcp.get("tcp.stream", 0)) if tcp.get("tcp.stream") is not None else None

            # TCP Flags
            tcp_flags = None
            if tcp:
                tcp_flags = {
                    "syn": tcp.get("tcp.flags.syn") == "1",
                    "ack": tcp.get("tcp.flags.ack") == "1",
                    "fin": tcp.get("tcp.flags.fin") == "1",
                    "rst": tcp.get("tcp.flags.reset") == "1",
                    "push": tcp.get("tcp.flags.push") == "1",
                    "raw": tcp.get("tcp.flags"),
                }

            # Protocol info layers
            tls = layers.get("tls", {})
            smtp = layers.get("smtp", {})
            imap = layers.get("imap", {})
            pop3 = layers.get("pop", {})

            # Determine primary protocol
            protocol = "TCP"
            if tls:
                protocol = "TLS"
            elif smtp:
                protocol = "SMTP"
            elif imap:
                protocol = "IMAP"
            elif pop3:
                protocol = "POP3"
            elif src_port in (25, 587, 465) or dst_port in (25, 587, 465):
                protocol = "SMTP"
            elif src_port in (143, 993) or dst_port in (143, 993):
                protocol = "IMAP"
            elif src_port in (110, 995) or dst_port in (110, 995):
                protocol = "POP3"

            # Clean protocol details
            tls_info = cls._extract_tls_info(tls) if tls else None
            smtp_info = cls._clean_layer(smtp) if smtp else None
            imap_info = cls._clean_layer(imap) if imap else None
            pop3_info = cls._clean_layer(pop3) if pop3 else None

            packet_record = {
                "packet_number": idx,
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_length": frame_len,
                "tcp_flags": tcp_flags,
                "tls_info": tls_info,
                "smtp_info": smtp_info,
                "imap_info": imap_info,
                "pop3_info": pop3_info,
                "stream_index": stream_idx,
            }
            packets.append(packet_record)

            # Stream aggregation
            if stream_idx is not None:
                if stream_idx not in streams_map:
                    streams_map[stream_idx] = {
                        "stream_index": stream_idx,
                        "client_ip": src_ip,
                        "client_port": src_port,
                        "server_ip": dst_ip,
                        "server_port": dst_port,
                        "protocol": protocol,
                        "has_starttls": False,
                        "starttls_packet_index": None,
                        "is_tls_encrypted": bool(tls),
                        "tls_version": tls_info.get("version") if tls_info else None,
                        "cipher_suite": tls_info.get("cipher_suite") if tls_info else None,
                        "packet_indices": [idx],
                    }
                else:
                    streams_map[stream_idx]["packet_indices"].append(idx)
                    if tls:
                        streams_map[stream_idx]["is_tls_encrypted"] = True
                        if tls_info and tls_info.get("version"):
                            streams_map[stream_idx]["tls_version"] = tls_info.get("version")
                        if tls_info and tls_info.get("cipher_suite"):
                            streams_map[stream_idx]["cipher_suite"] = tls_info.get("cipher_suite")
                    if protocol in ("SMTP", "IMAP", "POP3") and streams_map[stream_idx]["protocol"] in ("TCP", "UNKNOWN"):
                        streams_map[stream_idx]["protocol"] = protocol

        return packets, list(streams_map.values())

    @staticmethod
    def _clean_layer(layer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cleans verbose tshark keys into compact dictionaries."""
        return {k.replace(".", "_"): v for k, v in layer_data.items() if not k.startswith("_")}

    @classmethod
    def _extract_tls_info(cls, tls_layer: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts key TLS parameters from TShark tls layer."""
        version = (
            tls_layer.get("tls.handshake.version")
            or tls_layer.get("tls.record.version")
        )
        cipher_suite = tls_layer.get("tls.handshake.ciphersuite")
        server_name = tls_layer.get("tls.handshake.extensions_server_name")

        version_names = {
            "0x0301": "TLS 1.0",
            "0x0302": "TLS 1.1",
            "0x0303": "TLS 1.2",
            "0x0304": "TLS 1.3",
        }

        return {
            "version": version_names.get(str(version), str(version)),
            "cipher_suite": str(cipher_suite) if cipher_suite else None,
            "sni": server_name,
            "raw": cls._clean_layer(tls_layer),
        }
