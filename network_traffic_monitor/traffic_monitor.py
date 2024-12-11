import logging
import pyshark
import socket
import ipaddress
import time
from datetime import datetime
from alert_system.alert import trigger_alerts

class RuleEngine:
    def __init__(self, packet_threshold=10, time_window=60):
        self.packet_threshold = packet_threshold
        self.time_window = time_window
        self.ip_activity = {}
        self.known_good_external_ips = {
            "8.8.8.8", # Add more known-good hosts here
            "8.8.4.4", 
            "74.125.130.136", 
            "163.70.148.13", 
            "36.37.218.17",         
        }

    def register_packet(self, src_ip, dst_ip, is_external_src, is_external_dst):
        current_time = time.time()
        key = (src_ip, dst_ip)

        if key not in self.ip_activity:
            self.ip_activity[key] = [current_time]
        else:
            self.ip_activity[key].append(current_time)

        # Clean entries older than the time_window
        self.ip_activity[key] = [t for t in self.ip_activity[key] if current_time - t <= self.time_window]

    def check_rules(self, src_ip, dst_ip, is_external_src, is_external_dst):
        if is_external_src or is_external_dst:
            if dst_ip in self.known_good_external_ips or src_ip in self.known_good_external_ips:
                threshold = self.packet_threshold * 100  # Highly relaxed threshold for known-good hosts
            else:
                threshold = self.packet_threshold * 3   # Stricter threshold for unknown hosts
        else:
            threshold = self.packet_threshold

        key = (src_ip, dst_ip)
        if key in self.ip_activity and len(self.ip_activity[key]) > threshold:
            return True
        return False

class TrafficMonitor:
    def __init__(self, interface, max_packets=10000, local_network="192.168.0.0/16"):
        self.interface = interface
        self.packet_count = 0
        self.max_packets = max_packets
        self.capture_stopped = False
        self.local_ip = self.get_local_ip()
        self.local_network = ipaddress.ip_network(local_network)
        self.rule_engine = RuleEngine(packet_threshold=5, time_window=30)

        # Configure logging
        logging.basicConfig(
            filename="./logs/traffic_monitor.log",
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"[INFO] Local IP detected: {local_ip}")
            return local_ip
        except Exception as e:
            print(f"[ERROR] Could not retrieve local IP: {e}")
            return None

    def is_external_ip(self, ip):
        try:
            ip_addr = ipaddress.ip_address(ip)
            return ip_addr not in self.local_network
        except ValueError:
            return True

    def summarize_packet(self, packet):
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

    def analyze_packet(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            is_external_src = self.is_external_ip(src_ip)
            is_external_dst = self.is_external_ip(dst_ip)

            self.rule_engine.register_packet(src_ip, dst_ip, is_external_src, is_external_dst)

            if self.rule_engine.check_rules(src_ip, dst_ip, is_external_src, is_external_dst):
                trigger_alerts("Suspicious Activity Detected", src_ip, f"Unusual traffic pattern involving {src_ip} -> {dst_ip}")
                logging.warning(f"[SUSPICIOUS] Unusual traffic {src_ip} -> {dst_ip}")

    def log_packet(self, packet, verbose=False):
        self.packet_count += 1

        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            summary = self.summarize_packet(packet)
            logging.info(summary)

            if verbose:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}")

            self.analyze_packet(packet)

    def stop(self):
        if not self.capture_stopped:
            self.capture_stopped = True
            print(f"[INFO] Monitoring stopped. Total packets captured: {self.packet_count}")

    def start_capture(self, capture_filter="ip", verbose=False):
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
