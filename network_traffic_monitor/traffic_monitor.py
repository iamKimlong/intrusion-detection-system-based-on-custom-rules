import logging
import pyshark
import socket
import ipaddress
import time
import os
from datetime import datetime
from alert_system.alert import trigger_alerts

class RuleEngine:
    known_good_external_ips = {
        "8.8.8.8",    # Google DNS Server
        "8.8.4.4",    # Google Secondary DNS
        "1.1.1.1",    # Cloudflare DNS Server
        "1.0.0.1",    # Cloudflare Secondary DNS
        "74.125.130.136",  # Google Search/Services
        "142.250.191.174",  # Google API Services
        "172.217.16.196",  # Google Cloud Services
        "34.102.136.180",  # Google Web Services
        "163.70.148.13",  # External Service (Example from log)
        "36.37.218.17",  # Example IP from log (External Provider)
        "175.100.94.146",  # Another Service Provider (Example)
        "13.35.89.44",  # AWS Global Accelerator
        "52.94.237.0",  # AWS API Gateway
        "13.107.42.14",  # Microsoft Azure Endpoint
        "20.189.173.0",  # Microsoft Office 365 Services
        "17.57.146.100",  # Apple iCloud Services
        "17.253.144.10",  # Apple Services Endpoint
        "199.16.156.198",  # Twitter API Services
        "185.199.108.153",  # GitHub Global Network
        "52.58.78.16",  # AWS Elastic Load Balancer
        "104.26.11.78",  # Cloudflare Proxy Server
        "104.26.10.78",  # Cloudflare Backup Proxy
        "192.30.255.112",  # GitHub Server IP
        "185.60.216.35",  # Facebook Services
        "157.240.22.35",  # Facebook API Endpoint
        "172.67.13.78",  # Cloudflare Host IP
        "192.229.173.43",  # Akamai CDN
        "151.101.1.69",  # Fastly CDN (Common for APIs)
        "13.107.6.158",  # Skype Services
        "204.79.197.200",  # Bing Search Services
        "172.217.164.110",  # Google Web Cache
        "31.13.64.35",  # Facebook Messenger
        "157.240.221.35",  # Facebook Chat API
        "40.101.76.17",  # Microsoft 365 Email Services
        "64.233.187.99",  # Google Mail Servers
        "172.253.115.189",  # Google Ads Servers
        "84.17.57.98", # CDN services used to distribute web content efficiently
        "163.70.149.15", # External Service
        "74.125.68.91", # External Service
        "91.108.56.107", # External Service
        "203.0.113.5",  # Example Test IP
        "192.88.99.1",  # Deprecated Anycast IP
        "198.51.100.1",  # Test Network IP
        "45.33.32.156",  # Linode Server Example
        "104.131.114.102",  # DigitalOcean Example
        "207.154.239.48"  # Custom Service IP
    }

    def __init__(self, packet_threshold=10, time_window=30): # default scope
        self.packet_threshold = packet_threshold
        self.time_window = time_window
        self.ip_activity = {}


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
                threshold = self.packet_threshold * 1000  # Highly relaxed threshold for known good hosts
            else:
                threshold = self.packet_threshold * 1   # Stricter threshold for unknown hosts
        else:
            threshold = self.packet_threshold

        key = (src_ip, dst_ip)
        if key in self.ip_activity and len(self.ip_activity[key]) > threshold:
            return True
        return False

class TrafficMonitor:
    def __init__(self, interface, max_packets=10000, local_network="192.168.0.0/24"):
        self.interface = interface
        self.packet_count = 0
        self.max_packets = max_packets
        self.capture_stopped = False
        self.local_ip = self.get_local_ip()
        self.local_network = ipaddress.ip_network(local_network)
        self.rule_engine = RuleEngine(packet_threshold=10, time_window=30)

        # Ensure the logs directory exists
        # log_dir = os.path.join(os.path.dirname(__file__), "logs")

        # Ensure the logs directory exists one level up
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)

        # Configure logging
        log_file = os.path.join(log_dir, "ids.log")
        logging.basicConfig(
            filename=log_file,
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
                f"Packet #{self.packet_count} |"
                f" Protocol={protocol} |"
                f" Source={src_ip} |"
                f" Destination={dst_ip} |"
                f" Length={length} bytes"
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
                print(f"[IGNORED] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {summary}")

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
