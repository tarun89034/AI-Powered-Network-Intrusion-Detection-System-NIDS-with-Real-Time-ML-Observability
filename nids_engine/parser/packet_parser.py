"""
Packet Parser Module
Handles Deep Packet Inspection (DPI) equivalent logic.
Parses layers from scapy packets to identify TCP/UDP, DNS, HTTP, TLS.
"""

from typing import Dict, Any, Optional
import struct
from scapy.all import Packet, IP, TCP, UDP, DNS, Ether, Raw

class PacketParser:
    """
    Parses individual Scapy packets to extract metadata and perform DPI.
    """
    
    HTTP_METHODS = {b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"TRACE ", b"CONNECT "}
    
    @staticmethod
    def parse_packet(packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Extracts key information from a scapy packet.
        """
        if IP not in packet:
            return None
            
        ip_layer = packet[IP]
        
        parsed_data = {
            "timestamp": float(packet.time),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ip_len": ip_layer.len,
            "protocol": "OTHER",
            "src_port": 0,
            "dst_port": 0,
            "payload_len": 0,
            "dpi_protocol": "Unknown",
            "flags": "",
            "sni": None,
            "http_method": None,
            "dns_query": None
        }

        if TCP in packet:
            tcp_layer = packet[TCP]
            parsed_data["protocol"] = "TCP"
            parsed_data["src_port"] = tcp_layer.sport
            parsed_data["dst_port"] = tcp_layer.dport
            parsed_data["flags"] = str(tcp_layer.flags)
            
            if Raw in packet:
                payload = packet[Raw].load
                parsed_data["payload_len"] = len(payload)
                PacketParser._inspect_tcp_payload(parsed_data, payload)

        elif UDP in packet:
            udp_layer = packet[UDP]
            parsed_data["protocol"] = "UDP"
            parsed_data["src_port"] = udp_layer.sport
            parsed_data["dst_port"] = udp_layer.dport
            
            dns_layer = packet[DNS] if DNS in packet else None
            qdcount = int(getattr(dns_layer, "qdcount", 0) or 0)
            has_question = getattr(dns_layer, "qd", None) is not None
            if dns_layer is not None and (qdcount > 0 or has_question):
                parsed_data["dpi_protocol"] = "DNS"
                try:
                    if has_question:
                        parsed_data["dns_query"] = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                except Exception:
                    pass
                    
            elif Raw in packet:
                parsed_data["payload_len"] = len(packet[Raw].load)
                
        return parsed_data

    @staticmethod
    def _inspect_tcp_payload(parsed_data: Dict[str, Any], payload: bytes) -> None:
        """
        Performs simple DPI on TCP payload to identify HTTP or TLS.
        """
        if not payload:
            return
            
        # Check HTTP
        if any(payload.startswith(method) for method in PacketParser.HTTP_METHODS):
            parsed_data["dpi_protocol"] = "HTTP"
            method = payload.split(b" ")[0]
            parsed_data["http_method"] = method.decode('utf-8', errors='ignore')
            return
            
        # Check TLS (Client Hello)
        # Content Type 22 (Handshake), Version (0x0301, 0x0302, 0x0303), Handshake Type 1 (Client Hello)
        if len(payload) >= 43 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
            parsed_data["dpi_protocol"] = "TLS"
            sni = PacketParser._extract_sni(payload)
            if sni:
                parsed_data["sni"] = sni

    @staticmethod
    def _extract_sni(payload: bytes) -> Optional[str]:
        """
        Extracts Server Name Indication (SNI) from TLS Client Hello.
        Matches the C++ sni_extractor logic.
        """
        try:
            # Basic parsing of TLS records to find the SNI extension
            # Note: This is a simplified version; a robust implementation requires 
            # carefully parsing TLS variable-length fields.
            session_id_len = payload[43]
            offset = 44 + session_id_len
            
            if len(payload) <= offset + 2: return None
            cipher_suites_len = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            if len(payload) <= offset + 1: return None
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            
            if len(payload) <= offset + 2: return None
            extensions_len = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2
            
            end = offset + extensions_len
            while offset + 4 <= min(end, len(payload)):
                ext_type = struct.unpack(">H", payload[offset:offset+2])[0]
                ext_len = struct.unpack(">H", payload[offset+2:offset+4])[0]
                offset += 4
                
                if ext_type == 0x0000: # Server Name extension
                    # Parse Server Name List
                    if offset + 5 <= len(payload):
                        sn_list_len = struct.unpack(">H", payload[offset:offset+2])[0]
                        sn_type = payload[offset+2]
                        if sn_type == 0: # Hostname
                            sn_len = struct.unpack(">H", payload[offset+3:offset+5])[0]
                            sni_bytes = payload[offset+5:offset+5+sn_len]
                            return sni_bytes.decode('utf-8', errors='ignore')
                offset += ext_len
        except Exception:
            pass # Catch struct/index errors gracefully
            
        return None
