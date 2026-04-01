"""
Feature Extraction Module
Tracks active network flows and computes statistical features 
(similar to CICIDS datasets) for Machine Learning consumption.
"""

from typing import Dict, Any, List, Optional, Callable
import time
import math
from collections import defaultdict

class Flow:
    """
    Represents a bidirectional network flow and tracks its statistics.
    """
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, start_time: float):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = start_time
        self.last_time = start_time
        
        self.fwd_pkt_count = 0
        self.bwd_pkt_count = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        
        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.flow_flags = set()

    def add_packet(self, packet_data: Dict[str, Any]):
        """
        Updates flow statistics with a new packet.
        """
        self.last_time = packet_data['timestamp']
        ip_len = packet_data.get('ip_len', 0)
        
        # Check direction
        if packet_data['src_ip'] == self.src_ip and packet_data['src_port'] == self.src_port:
            self.fwd_pkt_count += 1
            self.fwd_bytes += ip_len
            self.fwd_pkt_lengths.append(ip_len)
        else:
            self.bwd_pkt_count += 1
            self.bwd_bytes += ip_len
            self.bwd_pkt_lengths.append(ip_len)
            
        if packet_data.get('flags'):
            self.flow_flags.update(list(packet_data['flags']))

    def get_features(self) -> Dict[str, Any]:
        """
        Calculates and returns the aggregated flow features.
        Matches a subset of the CICIDS2017 features.
        """
        flow_duration = max(self.last_time - self.start_time, 0.000001) # Avoid division by zero
        
        def safe_mean(lst): return sum(lst) / len(lst) if lst else 0
        def safe_std(lst, mean): return math.sqrt(sum((x - mean)**2 for x in lst) / len(lst)) if len(lst) > 1 else 0
        
        fwd_mean = safe_mean(self.fwd_pkt_lengths)
        bwd_mean = safe_mean(self.bwd_pkt_lengths)
        
        features = {
            "Flow Duration": flow_duration,
            "Total Fwd Packets": self.fwd_pkt_count,
            "Total Backward Packets": self.bwd_pkt_count,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": max(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            "Fwd Packet Length Min": min(self.fwd_pkt_lengths) if self.fwd_pkt_lengths else 0,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": safe_std(self.fwd_pkt_lengths, fwd_mean),
            "Bwd Packet Length Max": max(self.bwd_pkt_lengths) if self.bwd_pkt_lengths else 0,
            "Bwd Packet Length Min": min(self.bwd_pkt_lengths) if self.bwd_pkt_lengths else 0,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": safe_std(self.bwd_pkt_lengths, bwd_mean),
            "Flow Bytes/s": (self.fwd_bytes + self.bwd_bytes) / flow_duration,
            "Flow Packets/s": (self.fwd_pkt_count + self.bwd_pkt_count) / flow_duration,
            "FIN Flag Count": 1 if 'F' in self.flow_flags else 0,
            "SYN Flag Count": 1 if 'S' in self.flow_flags else 0,
            "RST Flag Count": 1 if 'R' in self.flow_flags else 0,
            "ACK Flag Count": 1 if 'A' in self.flow_flags else 0,
        }
        return features


class FeatureExtractor:
    """
    Manages active flows and extracts features periodically or upon flow termination.
    """
    def __init__(self, flow_timeout: float = 60.0, callback: Optional[Callable] = None):
        self.flows: Dict[str, Flow] = {}
        self.flow_timeout = flow_timeout
        self.callback = callback

    def _generate_flow_id(self, p: Dict[str, Any]) -> str:
        """Generates a bidirectional flow ID."""
        ips = sorted([p['src_ip'], p['dst_ip']])
        ports = sorted([p['src_port'], p['dst_port']])
        return f"{ips[0]}:{ports[0]}-{ips[1]}:{ports[1]}-{p['protocol']}"

    def process_packet(self, packet_data: Dict[str, Any]):
        """
        Processes a single packet dictionary, updates the corresponding flow,
        and checks for flow expiration/termination.
        """
        flow_id = self._generate_flow_id(packet_data)
        
        if flow_id not in self.flows:
            self.flows[flow_id] = Flow(
                flow_id=flow_id,
                src_ip=packet_data['src_ip'],
                dst_ip=packet_data['dst_ip'],
                src_port=packet_data['src_port'],
                dst_port=packet_data['dst_port'],
                protocol=packet_data['protocol'],
                start_time=packet_data['timestamp']
            )
            
        flow = self.flows[flow_id]
        flow.add_packet(packet_data)
        
        # Let the flow naturally time out in cleanup_expired_flows.
        # This enforces true Flow-based detection rather than premature packet-based splitting.

    def cleanup_expired_flows(self, current_time: float):
        """
        Emits and removes flows that have been inactive longer than the timeout.
        """
        expired_flows = [
            fid for fid, flow in self.flows.items() 
            if (current_time - flow.last_time) > self.flow_timeout
        ]
        for fid in expired_flows:
            self._emit_flow(fid)

    def flush_all(self):
        """
        Emits ALL remaining flows regardless of timeout.
        Called during engine shutdown to ensure no data is lost.
        """
        remaining = list(self.flows.keys())
        for fid in remaining:
            self._emit_flow(fid)

    def _emit_flow(self, flow_id: str):
        """
        Extracts features for a flow, triggers the callback, and deletes it.
        """
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            features = flow.get_features()
            
            # Attach basic metadata for dashboard/storage
            result = {
                "flow_id": flow_id,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "start_time": flow.start_time,
                "end_time": flow.last_time,
                "features": features
            }
            
            if self.callback:
                self.callback(result)
                
            del self.flows[flow_id]
