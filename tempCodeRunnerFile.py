#capture_packets.py
import logging
import os
from collections import defaultdict
import pyshark
from alert import main as trigger_alert  # Import the alert system for triggering alerts
import time

# Class to monitor network traffic and detect attacks
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

        self.capture_stopped = False

    def check_packet(self, packet):
        # Stop after max_packets
        if self.packet_count >= self.max_packets or self.capture_stopped:
            self.stop()
            return

        self.packet_count += 1
        # Check the packet against rules
        self.check_packet_with_rules(packet)
        # Log packet details
        self.log_packet(packet)

    def check_packet_with_rules(self, packet):
        """Check each packet against detection rules"""
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Port Scanning Detection
            if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):  # Ensure transport layer is present
                dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else packet.udp.dstport
                self.port_scans[src_ip].add(dst_port)
                if len(self.port_scans[src_ip]) > self.port_scan_threshold:
                    logging.info(f"Port Scanning detected from {src_ip}")
                    print(f"Alert: Port Scanning detected from {src_ip}")
                    trigger_alert()

            # DDoS Detection
            self.ddos_attempts[src_ip] += 1
            if self.ddos_attempts[src_ip] > self.ddos_threshold:
                logging.info(f"DDoS detected from {src_ip}")
                print(f"Alert: DDoS detected from {src_ip}")
                trigger_alert()

            # Pass traffic and a rule function to execute_rule
            self.execute_rule(packet)  # Execute rule with packet

    def execute_rule(self, packet):
        """A sample rule function that can be used to detect traffic patterns"""
        if hasattr(packet, 'ip') and packet.ip.src == '192.168.0.1':  # Example rule based on IP
            logging.info(f"Custom rule matched for packet from {packet.ip.src}")
            print(f"Custom Rule Matched: {packet.ip.src}")
            trigger_alert()

    def log_packet(self, packet):
        """Log detailed packet information including source, destination, and protocol"""
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A'
            length = packet.length if hasattr(packet, 'length') else 'N/A'

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

            logging.info(f"Packet {self.packet_count} - Source: {src_ip}:{src_port}, Dest: {dst_ip}:{dst_port}, "
                         f"Protocol: {protocol}, Length: {length} bytes, Flags: {flags}")
            print(f"Packet {self.packet_count}: Source IP: {src_ip}:{src_port}, Destination IP: {dst_ip}:{dst_port}, "
                  f"Protocol: {protocol}, Length: {length} bytes, Flags: {flags}")
        else:
            print(f"Packet {self.packet_count}: No IP layer found")

    def stop(self):
        """Stop the packet capture and show the total packet count"""
        if not self.capture_stopped:
            self.capture_stopped = True
            print(f"Monitoring stopped. Total packets captured: {self.packet_count}")
    

def start_capture(interface="wlp2s0", capture_filter="ip", max_packets=100):
    # Initialize the traffic monitor with the custom packet limit
    monitor = TrafficMonitor(max_packets=max_packets)  

    # Start capturing packets
    print(f"Starting packet capture on {interface}...")
    
    # Use PyShark to capture packets
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    
    # Set up the packet processing function
    for packet in capture.sniff_continuously():
        monitor.check_packet(packet)  # Process and log the packet
        time.sleep(0.1)  # Introduce a small delay for better performance control
    print("Packet capture stopped.")


if __name__ == "__main__":
    # You can modify the interface here or leave it as the default ("wlp2s0")
    start_capture(interface="wlp2s0", max_packets=100)
