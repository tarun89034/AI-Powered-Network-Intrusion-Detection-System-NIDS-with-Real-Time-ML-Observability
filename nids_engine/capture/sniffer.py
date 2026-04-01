"""
Packet Capture Module
Responsible for live sniffing using scapy or reading from a PCAP file.
Sends parsed packets to the feature extractor asynchronously.
"""

from scapy.all import sniff, PcapReader
import threading
from typing import Callable, Optional
from nids_engine.parser.packet_parser import PacketParser

class PacketSniffer:
    """
    Sniffs packets from a given interface or PCAP file and triggers a callback.
    """
    
    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None, callback: Optional[Callable] = None):
        """
        Initializes the sniffer.
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.callback = callback
        self._stop_event = threading.Event()
        self.sniff_thread = None

    def start(self):
        """
        Starts the packet capture in a background thread.
        """
        self._stop_event.clear()
        if self.pcap_file:
            self.sniff_thread = threading.Thread(target=self._read_pcap, daemon=True)
        else:
            self.sniff_thread = threading.Thread(target=self._start_sniffing, daemon=True)
            
        self.sniff_thread.start()

    def stop(self):
        """
        Stops the packet capture.
        """
        self._stop_event.set()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2.0)

    def _process_packet(self, packet):
        """
        Internal callback for scapy sniff to process and route packets.
        """
        if self._stop_event.is_set():
            return True # Stops scapy sniff
            
        parsed_packet = PacketParser.parse_packet(packet)
        if parsed_packet and self.callback:
            self.callback(parsed_packet)
        
        # We do not return False here. Scapy's prn callback will print the return value
        # by default if it's not None, which floods the console with "False" per packet.

    def _start_sniffing(self):
        """
        Runs the scapy live sniffer.
        """
        kwargs = {"prn": self._process_packet, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
            
        sniff(**kwargs, stop_filter=lambda p: self._stop_event.is_set())

    def _read_pcap(self):
        """
        Reads packets from a PCAP file sequentially.
        """
        try:
            with PcapReader(self.pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    if self._stop_event.is_set():
                        break
                    self._process_packet(packet)
        except Exception as e:
            print(f"Error reading PCAP: {e}")
