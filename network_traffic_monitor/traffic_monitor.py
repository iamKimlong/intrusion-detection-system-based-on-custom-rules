import logging
import pyshark
import time
from collections import defaultdict
from alert import trigger_alerts

class TrafficMonitor:
    def __init__(self, max_packets=100):
        self.packet_count = 0
        self.max_packets = max_packets
        self.capture_stopped = False
        logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

    def detect_packet_type(self, packet):
        """Detect packet type based on transport layer."""
        if hasattr(packet, 'tcp'):
            return "TCP"
        elif hasattr(packet, 'udp'):
            return "UDP"
        elif hasattr(packet, 'icmp'):
            return "ICMP"
        else:
            return "Other"

    def check_packet(self, packet):
        if self.packet_count >= self.max_packets or self.capture_stopped:
            self.stop()
            return

        self.packet_count += 1
        self.log_packet(packet)

    def log_packet(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = self.detect_packet_type(packet)
            length = packet.length if hasattr(packet, 'length') else 'N/A'

            logging.info(f"[PACKET {self.packet_count}] {protocol} from {src_ip} to {dst_ip}, Length: {length} bytes")
            print(f"[PACKET {self.packet_count}] Type: {protocol}, Source: {src_ip}, Destination: {dst_ip}, Length: {length} bytes")

            # Trigger alert for testing purposes
            trigger_alerts(f"Suspicious {protocol} Packet", src_ip, f"{protocol} traffic from {src_ip} to {dst_ip}")

    def stop(self):
        if not self.capture_stopped:
            self.capture_stopped = True
            print(f"[INFO] Monitoring stopped. Total packets captured: {self.packet_count}")

    def start_capture(self, interface="wlp2s0", capture_filter="ip", max_packets=100):
        self.max_packets = max_packets
        capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
        print(f"[INFO] Starting packet capture on {interface} with filter '{capture_filter}'...")

        for packet in capture.sniff_continuously():
            self.check_packet(packet)
            time.sleep(0.1)
        print("[INFO] Packet capture stopped.")