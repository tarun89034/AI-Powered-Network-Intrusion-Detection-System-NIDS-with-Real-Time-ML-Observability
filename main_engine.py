"""Main runtime orchestrator for capture -> features -> inference -> storage."""

import argparse
import json
import logging
import os
import smtplib
import threading
import time
from email.message import EmailMessage
from queue import Queue
from urllib import request as urlrequest

from nids_engine.capture.sniffer import PacketSniffer
from nids_engine.features.feature_extractor import FeatureExtractor
from nids_engine.ml.model_manager import ModelManager
from nids_engine.storage.db import FlowDatabase


def configure_logging(level: str = "INFO") -> None:
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/nids.log", encoding="utf-8"),
        ],
    )


def send_email_alert(subject: str, body: str) -> None:
    smtp_host = os.getenv("NIDS_SMTP_HOST")
    smtp_port = int(os.getenv("NIDS_SMTP_PORT", "587"))
    smtp_user = os.getenv("NIDS_SMTP_USER")
    smtp_password = os.getenv("NIDS_SMTP_PASSWORD")
    sender = os.getenv("NIDS_ALERT_FROM")
    recipient = os.getenv("NIDS_ALERT_TO")

    if not all([smtp_host, smtp_user, smtp_password, sender, recipient]):
        return

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)


def classify_attack_heuristic(flow_data: dict) -> str:
    """Provides a coarse attack label when only anomaly output is available."""
    features = flow_data.get("features", {})
    pkt_rate = float(features.get("Flow Packets/s", 0))
    syn_count = int(features.get("SYN Flag Count", 0))
    fwd_packets = int(features.get("Total Fwd Packets", 0))
    dst_port = int(flow_data.get("dst_port", 0))

    if pkt_rate > 1000 or fwd_packets > 500:
        return "DDoS"
    if syn_count > 0 and pkt_rate > 300:
        return "SYN Flood"
    if dst_port in {22, 3389, 21} and fwd_packets > 20:
        return "Brute Force"
    if dst_port in {53} and pkt_rate > 400:
        return "DNS Abuse"
    return "Suspicious Traffic"

class NIDSEngine:
    def __init__(self, interface=None, pcap_file=None, flow_timeout: float = 30.0, api_url: str | None = None):
        self.logger = logging.getLogger("nids.engine")
        self.interface = interface
        self.pcap_file = pcap_file
        self.api_url = api_url
        
        self.packet_queue = Queue()
        self.flow_queue = Queue()
        
        self.sniffer = PacketSniffer(
            interface=interface, 
            pcap_file=pcap_file, 
            callback=self.packet_queue.put
        )
        self.extractor = FeatureExtractor(
            flow_timeout=flow_timeout,
            callback=self.flow_queue.put
        )
        self.ml_manager = ModelManager()
        self.db = FlowDatabase()
        
        self.running = False

    def _packet_processing_worker(self):
        """Worker to move packets from queue to feature extractor."""
        last_cleanup = time.time()
        while self.running:
            if not self.packet_queue.empty():
                packet = self.packet_queue.get()
                self.extractor.process_packet(packet)
            else:
                time.sleep(0.01)

            # Run cleanup periodically (every 2 seconds), even during heavy traffic
            now = time.time()
            if now - last_cleanup >= 2.0:
                self.extractor.cleanup_expired_flows(now)
                last_cleanup = now

    def _flow_inference_worker(self):
        """Worker to run ML inference on completed flows and store in DB."""
        while self.running:
            if not self.flow_queue.empty():
                flow_data = self.flow_queue.get()
                
                # ML Inference
                is_anomaly, attack_type = self.ml_manager.predict(flow_data["features"])
                if is_anomaly and attack_type == "Anomaly (Zero-Day)":
                    attack_type = classify_attack_heuristic(flow_data)
                
                if is_anomaly:
                    alert = f"{attack_type} detected: {flow_data['src_ip']} -> {flow_data['dst_ip']}"
                    self.logger.warning("ALERT | %s", alert)
                    try:
                        send_email_alert("NIDS Alert", alert)
                    except Exception as exc:
                        self.logger.error("Email alert failed: %s", exc)
                else:
                    self.logger.info(
                        "FLOW | Normal: %s -> %s | %s",
                        flow_data["src_ip"],
                        flow_data["dst_ip"],
                        flow_data["protocol"],
                    )
                
                # Store in DB
                if self.api_url:
                    try:
                        payload = json.dumps(flow_data).encode("utf-8")
                        req = urlrequest.Request(
                            f"{self.api_url.rstrip('/')}/api/ingest_flow",
                            data=payload,
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        urlrequest.urlopen(req, timeout=2).read()
                    except Exception as exc:
                        self.logger.error("Flow API ingest failed, falling back to DB: %s", exc)
                        self.db.insert_flow(flow_data, is_anomaly, attack_type)
                else:
                    self.db.insert_flow(flow_data, is_anomaly, attack_type)
            else:
                time.sleep(0.1)

    def start(self):
        """Starts all pipeline components."""
        self.running = True
        
        # Start workers
        threading.Thread(target=self._packet_processing_worker, daemon=True).start()
        threading.Thread(target=self._flow_inference_worker, daemon=True).start()
        
        # Start sniffer
        self.logger.info("Starting packet sniffer")
        self.sniffer.start()

    def stop(self):
        """Stops the pipeline and flushes remaining flows."""
        self.running = False
        self.sniffer.stop()

        # Flush all in-progress flows through the ML pipeline before exiting
        self.logger.info("Flushing %d remaining flows...", len(self.extractor.flows))
        self.extractor.flush_all()

        # Process any remaining items in the flow queue
        while not self.flow_queue.empty():
            flow_data = self.flow_queue.get()
            is_anomaly, attack_type = self.ml_manager.predict(flow_data["features"])
            if is_anomaly and attack_type == "Anomaly (Zero-Day)":
                attack_type = classify_attack_heuristic(flow_data)
            self.db.insert_flow(flow_data, is_anomaly, attack_type)

        self.logger.info("Engine stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered NIDS engine runtime")
    parser.add_argument("-i", "--interface", type=str, help="Network interface for live capture")
    parser.add_argument("-r", "--read", type=str, help="PCAP file path for offline replay")
    parser.add_argument("--flow-timeout", type=float, default=30.0, help="Flow timeout seconds")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level")
    parser.add_argument("--api-url", type=str, help="Optional backend URL for flow ingestion")
    args = parser.parse_args()

    configure_logging(args.log_level)

    engine = NIDSEngine(
        interface=args.interface,
        pcap_file=args.read,
        flow_timeout=args.flow_timeout,
        api_url=args.api_url,
    )
    engine.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
