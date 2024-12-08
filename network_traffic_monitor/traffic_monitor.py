import logging
import pyshark
from datetime import datetime
from alert_system.alert import trigger_alerts

class TrafficMonitor:
    def __init__(self, max_packets=100):
        self.packet_count = 0
        self.max_packets = max_packets
        self.capture_stopped = False

        # Configure logging with date and time
        logging.basicConfig(
            filename="traffic_monitor.log",
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def summarize_packet(self, packet):
        # Summarize packet details
        try:
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else "N/A"
            length = packet.length if hasattr(packet, 'length') else "N/A"

            summary = (
                f"Packet #{self.packet_count}: "
                f"Protocol={protocol}, "
                f"Source={src_ip}, "
                f"Destination={dst_ip}, "
                f"Length={length} bytes"
            )
            return summary
        except Exception as e:
            return f"[ERROR] Failed to summarize packet: {e}"

    def log_packet(self, packet, verbose=False):
        # Log and display packet details
        self.packet_count += 1

        summary = self.summarize_packet(packet)
        
        # Log to file with date and time
        logging.info(summary)

        if verbose:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}")

        # Trigger alerts if required
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            trigger_alerts("Suspicious Packet Detected", src_ip, f"Traffic from {src_ip} to {dst_ip}")

    def stop(self):
        if not self.capture_stopped:
            self.capture_stopped = True
            print(f"[INFO] Monitoring stopped. Total packets captured: {self.packet_count}")

    def start_capture(self, interface="wlo1", capture_filter="ip", max_packets=100, verbose=False):
        """Start the packet capture and display verbose output if enabled."""
        self.max_packets = max_packets
        capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
        print(f"[INFO] Starting packet capture on {interface} with filter '{capture_filter}'...")

        try:
            for packet in capture.sniff_continuously():
                self.log_packet(packet, verbose=verbose)
                if self.packet_count >= self.max_packets:
                    break
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
        print("[INFO] Packet capture stopped.")
