import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from scapy.all import rdpcap, IP, IPv6, TCP, Raw
from app.services.protocol_identifier import ProtocolIdentifier
from app.services.tls_handshake_parser import TLSHandshakeParser

logger = logging.getLogger(__name__)


class ScapyParser:
    """Dissects PCAP packets using native Scapy, reassembles TCP sessions, and inspects TLS & payloads."""

    @classmethod
    def parse_pcap(cls, pcap_path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Parses PCAP with Scapy, extracting packet records and reconstructing TCP sessions.
        Returns: (extracted_packets, reconstructed_streams)
        """
        logger.info(f"Parsing capture with Scapy: {pcap_path}")
        packets_pcap = rdpcap(str(pcap_path))

        extracted_packets: List[Dict[str, Any]] = []
        # Grouping key: sorted((ip1, port1), (ip2, port2)) -> stream record
        session_map: Dict[Tuple, Dict[str, Any]] = {}
        stream_counter = 0

        for idx, pkt in enumerate(packets_pcap, start=1):
            if not pkt.haslayer(TCP):
                continue

            # IP Extraction
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue

            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            timestamp = float(pkt.time)
            pkt_len = len(pkt)

            # TCP Flags
            flags = tcp.flags
            tcp_flags = {
                "syn": bool(flags & 0x02),
                "ack": bool(flags & 0x10),
                "fin": bool(flags & 0x01),
                "rst": bool(flags & 0x04),
                "push": bool(flags & 0x08),
                "urg": bool(flags & 0x20),
                "raw": str(flags),
            }

            # Payload extraction
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

            # 4-Tuple stream grouping
            ep1 = (src_ip, src_port)
            ep2 = (dst_ip, dst_port)
            session_key = tuple(sorted([ep1, ep2]))

            if session_key not in session_map:
                stream_counter += 1
                session_map[session_key] = {
                    "stream_index": stream_counter,
                    "client_ip": src_ip,
                    "client_port": src_port,
                    "server_ip": dst_ip,
                    "server_port": dst_port,
                    "protocol": ProtocolIdentifier.identify_protocol_by_port(src_port, dst_port),
                    "has_starttls": False,
                    "starttls_packet_index": None,
                    "is_tls_encrypted": False,
                    "tls_version": None,
                    "cipher_suite": None,
                    "has_pfs": False,
                    "key_exchange": None,
                    "sni": None,
                    "client_cipher_suites": [],
                    "certificates": [],
                    "packet_indices": [],
                    "payloads": [],
                }

            current_stream = session_map[session_key]
            current_stream["packet_indices"].append(idx)
            current_stream["payloads"].append(payload)

            # Check if this packet contains a TLS record
            tls_handshake = TLSHandshakeParser.parse_tls_record(payload)
            tls_info = None
            smtp_info = None
            imap_info = None
            pop3_info = None

            proto = current_stream["protocol"]

            if tls_handshake:
                protocol = "TLS"
                current_stream["is_tls_encrypted"] = True
                tls_info = {
                    "record_version": tls_handshake.get("record_version"),
                    "messages": [m["type"] for m in tls_handshake.get("messages", [])],
                }

                for msg in tls_handshake.get("messages", []):
                    m_type = msg.get("type")
                    if m_type == "ClientHello":
                        ch = msg.get("data", {})
                        tls_info["handshake_type"] = "ClientHello"
                        tls_info["version"] = ch.get("version")
                        tls_info["sni"] = ch.get("sni")
                        if not current_stream.get("tls_version") and ch.get("version"):
                            current_stream["tls_version"] = ch.get("version")
                        if ch.get("cipher_suites"):
                            current_stream["client_cipher_suites"] = ch.get("cipher_suites")
                        if ch.get("sni"):
                            current_stream["sni"] = ch.get("sni")

                    elif m_type == "ServerHello":
                        sh = msg.get("data", {})
                        tls_info["handshake_type"] = "ServerHello"
                        tls_info["version"] = sh.get("version")
                        tls_info["cipher_suite"] = sh.get("cipher_suite", {}).get("name")
                        tls_info["has_pfs"] = sh.get("has_pfs", False)
                        tls_info["key_exchange"] = sh.get("key_exchange")

                        current_stream["tls_version"] = sh.get("version")
                        current_stream["cipher_suite"] = sh.get("cipher_suite", {}).get("name")
                        current_stream["has_pfs"] = sh.get("has_pfs", False)
                        current_stream["key_exchange"] = sh.get("key_exchange")

                    elif m_type == "Certificate":
                        certs = msg.get("certificates", [])
                        tls_info["handshake_type"] = "Certificate"
                        tls_info["cert_count"] = len(certs)
                        current_stream["certificates"].extend(certs)

            elif payload.startswith(b"\x17\x03"):  # TLS Application Data
                protocol = "TLS"
                current_stream["is_tls_encrypted"] = True
                tls_info = {"content_type": 0x17, "description": "TLS Application Data (Encrypted)"}

            else:
                detected_proto, proto_info = ProtocolIdentifier.inspect_payload_signature(payload, default_protocol=proto)
                if detected_proto != "UNKNOWN":
                    protocol = detected_proto
                    if current_stream["protocol"] == "UNKNOWN":
                        current_stream["protocol"] = detected_proto

                    if detected_proto == "SMTP":
                        smtp_info = proto_info
                    elif detected_proto == "IMAP":
                        imap_info = proto_info
                    elif detected_proto == "POP3":
                        pop3_info = proto_info

                    # STARTTLS transition check
                    if proto_info.get("command") in ("STARTTLS", "STLS"):
                        current_stream["has_starttls"] = True
                        current_stream["starttls_packet_index"] = idx
                else:
                    protocol = proto if proto != "UNKNOWN" else "TCP"

            record = {
                "packet_number": idx,
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_length": pkt_len,
                "tcp_flags": tcp_flags,
                "tls_info": tls_info,
                "smtp_info": smtp_info,
                "imap_info": imap_info,
                "pop3_info": pop3_info,
                "stream_index": current_stream["stream_index"],
            }
            extracted_packets.append(record)

        # Post-process streams for STARTTLS confirmation
        reconstructed_streams = []
        for stream in session_map.values():
            proto, has_st, st_idx = ProtocolIdentifier.detect_stream_protocol(
                stream["client_port"], stream["server_port"], stream.pop("payloads", [])
            )
            if proto != "UNKNOWN":
                stream["protocol"] = proto
            if has_st:
                stream["has_starttls"] = True
                stream["starttls_packet_index"] = st_idx
            reconstructed_streams.append(stream)

        return extracted_packets, reconstructed_streams
