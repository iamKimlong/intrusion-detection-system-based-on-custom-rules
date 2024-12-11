import logging
import pyshark
import socket
import ipaddress
from datetime import datetime
from alert_system.alert import trigger_alerts

class TrafficMonitor:
    def __init__(self, interface, max_packets=10000, local_network="192.168.0.0/16"):
        self.interface = interface
        self.packet_count = 0
        self.max_packets = max_packets
        self.capture_stopped = False
        self.local_ip = self.get_local_ip()
        self.local_network = ipaddress.ip_network(local_network)

        # Configure logging
        logging.basicConfig(
            filename="./logs/traffic_monitor.log",
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def get_local_ip(self):
        # Get the system's local IP address.
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"[INFO] Local IP detected: {local_ip}")
            return local_ip
        except Exception as e:
            print(f"[ERROR] Could not retrieve local IP: {e}")
            return None

    def is_external_ip(self, ip):
        # Check if IP is outside the local network.
        try:
            ip_addr = ipaddress.ip_address(ip)
            return ip_addr not in self.local_network
        except ValueError:
            return True  # If IP is invalid, consider it external

    def summarize_packet(self, packet):
        # Summarize packet details.
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
        # Log and display packet details, ignoring external IPs.
        self.packet_count += 1

        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Ignore external IPs
            if self.is_external_ip(src_ip) or self.is_external_ip(dst_ip):
                if verbose:
                    print(f"[IGNORED] External IP: {src_ip} -> {dst_ip}")
                return  # Skip processing the packet entirely

        # Summarize the packet
        summary = self.summarize_packet(packet)
        
        # Log the packet to file
        logging.info(summary)

        # Print to terminal if verbose is enabled
        if verbose:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}")

        # Trigger alerts if necessary
        if hasattr(packet, 'ip'):
            trigger_alerts("Suspicious Packet Detected", src_ip, f"Traffic from {src_ip} to {dst_ip}")

    def stop(self):
        # Stop the packet capture.
        if not self.capture_stopped:
            self.capture_stopped = True
            print(f"[INFO] Monitoring stopped. Total packets captured: {self.packet_count}")

    def start_capture(self, capture_filter="ip", verbose=False):
        # Start the packet capture 
        capture = pyshark.LiveCapture(interface=self.interface, display_filter=capture_filter)
        print(f"[INFO] Starting packet capture on {self.interface} with filter '{capture_filter}'...")

        try:
            for packet in capture.sniff_continuously():
                self.log_packet(packet, verbose=verbose)
                if self.packet_count >= self.max_packets:
                    break
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
        print("[INFO] Packet capture stopped.")
