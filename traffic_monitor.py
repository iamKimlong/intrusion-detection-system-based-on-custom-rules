#traffic_monitor.py
import logging
from collections import defaultdict

class TrafficMonitor:
    def __init__(self, max_packets=100, port_scan_threshold=10, ddos_threshold=100, brute_force_threshold=5, dos_threshold=1000):
        # Store max_packets as an instance variable
        self.packet_count = 0
        self.max_packets = max_packets  # Max number of packets to capture
        logging.basicConfig(filename="traffic_monitor.log", level=logging.INFO)

        # Thresholds for various attack detections (customizable)
        self.port_scan_threshold = port_scan_threshold
        self.ddos_threshold = ddos_threshold
        self.brute_force_threshold = brute_force_threshold
        self.dos_threshold = dos_threshold

        # Data structures for malicious activity detection
        self.port_scans = defaultdict(set)  # To track ports accessed by IPs
        self.ddos_attempts = defaultdict(int)  # To track high-volume traffic to specific IPs
        self.failed_logins = defaultdict(int)  # To track failed login attempts
        self.dos_attempts = defaultdict(int)  # To track DoS attempts from a single IP

    def check_packet(self, packet):
        # Stop after max_packets
        if self.packet_count >= self.max_packets:
            self.stop()
            return

        self.packet_count += 1
        
        # Detect Port Scanning
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            self.detect_port_scanning(packet)

        # Detect DDoS Attacks
        if hasattr(packet, 'ip'):
            self.detect_ddos(packet)

        # Detect Brute-Force Logins
        if hasattr(packet, 'ip') and hasattr(packet, 'http'):
            self.detect_brute_force_logins(packet)

        # Detect DoS Attacks
        if hasattr(packet, 'ip'):
            self.detect_dos(packet)

        # Log packet details
        self.log_packet(packet)

    def detect_port_scanning(self, packet):
        src_ip = packet.ip.src
        dst_port = packet.tcp.dstport
        self.port_scans[src_ip].add(dst_port)

        if len(self.port_scans[src_ip]) > self.port_scan_threshold:  # Use dynamic threshold
            print(f"Port scan detected from {src_ip}")
            logging.info(f"Port scan detected from {src_ip}")

    def detect_ddos(self, packet):
        dst_ip = packet.ip.dst
        self.ddos_attempts[dst_ip] += 1

        if self.ddos_attempts[dst_ip] > self.ddos_threshold:  # Use dynamic threshold
            print(f"DDoS attack detected against {dst_ip}")
            logging.info(f"DDoS attack detected against {dst_ip}")

    def detect_brute_force_logins(self, packet):
        if "POST" in packet.http.field_names and "login" in packet.http.get_raw():
            src_ip = packet.ip.src
            self.failed_logins[src_ip] += 1

            if self.failed_logins[src_ip] > self.brute_force_threshold:  # Use dynamic threshold
                print(f"Brute-force login attempt detected from {src_ip}")
                logging.info(f"Brute-force login attempt detected from {src_ip}")

    def detect_dos(self, packet):
        src_ip = packet.ip.src
        self.dos_attempts[src_ip] += 1

        if self.dos_attempts[src_ip] > self.dos_threshold:  # Use dynamic threshold
            print(f"DoS attack detected from {src_ip}")
            logging.info(f"DoS attack detected from {src_ip}")

    def log_packet(self, packet):
        """Log detailed packet information including source, destination, and protocol"""
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A'
            length = packet.length if hasattr(packet, 'length') else 'N/A'

            # For TCP/UDP packets, extract port and flag details
            if hasattr(packet, 'tcp'):
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                flags = packet.tcp.flags
            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                flags = 'N/A'
            else:
                src_port = dst_port = 'N/A'
                flags = 'N/A'

            # Log the packet details
            logging.info(f"Packet {self.packet_count} - Source: {src_ip}:{src_port}, Dest: {dst_ip}:{dst_port}, "
                         f"Protocol: {protocol}, Length: {length} bytes, Flags: {flags}")
            
            # Print the packet details
            print(f"Packet {self.packet_count}: Source IP: {src_ip}:{src_port}, Destination IP: {dst_ip}:{dst_port}, "
                  f"Protocol: {protocol}, Length: {length} bytes, Flags: {flags}")
        else:
            print(f"Packet {self.packet_count}: No IP layer found")

        # Check if the packet is ARP and log ARP details
        if hasattr(packet, 'arp'):
            logging.info(f"ARP Packet - Sender: {packet.arp.src_ip}, Target: {packet.arp.dst_ip}")
            print(f"Packet {self.packet_count}: ARP Packet - Sender: {packet.arp.src_ip}, Target: {packet.arp.dst_ip}")
        
        # Check for ICMP packets and log the ICMP information
        if hasattr(packet, 'icmp'):
            logging.info(f"ICMP Packet - Type: {packet.icmp.type}, Code: {packet.icmp.code}, Source: {packet.ip.src}, Dest: {packet.ip.dst}")
            print(f"Packet {self.packet_count}: ICMP Packet - Type: {packet.icmp.type}, Code: {packet.icmp.code}, "
                  f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")

    def stop(self):
        # Print the final count of captured packets
        print(f"Monitoring stopped. Total packets captured: {self.packet_count}")
