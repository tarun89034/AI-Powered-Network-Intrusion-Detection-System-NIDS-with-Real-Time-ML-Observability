import argparse
from nids_engine.capture.sniffer import PacketSniffer
import time

def packet_callback(parsed_data):
    """
    Callback function that receives parsed packet dictionary.
    """
    if parsed_data:
        # Example output for demonstration
        print(f"[{parsed_data['timestamp']}] {parsed_data['protocol']} "
              f"{parsed_data['src_ip']}:{parsed_data['src_port']} -> "
              f"{parsed_data['dst_ip']}:{parsed_data['dst_port']} "
              f"| DPI: {parsed_data['dpi_protocol']} "
              f"| Flags: {parsed_data['flags']} "
              f"| SNI/HTTP/DNS: {parsed_data.get('sni') or parsed_data.get('http_method') or parsed_data.get('dns_query')}")

def main():
    parser = argparse.ArgumentParser(description="Python NIDS Engine - Packet Capture")
    parser.add_argument('-i', '--interface', type=str, help='Interface to sniff on')
    parser.add_argument('-r', '--read', type=str, help='Read from pcap file')
    args = parser.parse_args()

    sniffer = PacketSniffer(interface=args.interface, pcap_file=args.read, callback=packet_callback)
    
    print("Starting Packet Capture...")
    sniffer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping capture...")
        sniffer.stop()

if __name__ == "__main__":
    main()
