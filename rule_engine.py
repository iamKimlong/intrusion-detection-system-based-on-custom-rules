import logging
import os
import random
from alert import main as trigger_alert  # Import the alert system for triggering alerts
import pyshark

# Define the rules
def detect_port_scanning(traffic):
    """Detects port scanning by monitoring multiple connection attempts on different ports."""
    port_access_count = {}
    for packet in traffic:
        port = packet.get("port")
        if port:
            port_access_count[port] = port_access_count.get(port, 0) + 1
    return any(count > 5 for count in port_access_count.values())

def detect_ddos(traffic):
    """Detects DDoS attacks by monitoring an unusually high volume of traffic."""
    return len(traffic) > 50

def detect_brute_force(traffic):
    """Detects brute-force login attempts based on the number of failed login attempts."""
    failed_attempts = {}
    for packet in traffic:
        src_ip = packet.get("src_ip")
        if "login" in packet.get("data", ""):  # Check for login attempts
            failed_attempts[src_ip] = failed_attempts.get(src_ip, 0) + 1
    return any(attempts > 5 for attempts in failed_attempts.values())  # Threshold for brute-force detection

def detect_dos(traffic):
    """Detects DoS attacks by monitoring repeated requests from the same source IP."""
    src_ip_count = {}
    for packet in traffic:
        src_ip = packet.get("src_ip")
        src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1
    return any(count > 50 for count in src_ip_count.values())  # Threshold for DoS detection

# Log configuration
def setup_logging(rule_name):
    """Set up logging for a specific rule."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, f"{rule_name}.log")
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        filemode="a",
    )
    return log_file

# Rule execution engine
def execute_rule(traffic, rule_function):
    """Execute the rule on the provided traffic"""
    if rule_function(traffic):  # If the rule function returns True, trigger an action
        print(f"Rule matched for traffic: {traffic}")
    else:
        print(f"No match for traffic: {traffic}")


# Traffic Capture and Rule Application
def monitor_traffic(interface="wlp2s0", packet_limit=100):
    print("Starting packet capture...")
    capture = pyshark.LiveCapture(interface=interface)  # Replace with your network interface
    traffic = []

    for packet in capture.sniff_continuously(packet_count=packet_limit):  # Limit to a certain number of packets
        packet_info = {
            "port": packet.transport_layer.dstport if hasattr(packet, 'tcp') else None,
            "data": str(packet),
            "src_ip": packet.ip.src
        }
        traffic.append(packet_info)

    print(f"Captured {len(traffic)} packets.")
    
    # Automatically apply all rules
    rules = {
        "Port Scanning": detect_port_scanning,
        "DDoS Attack": detect_ddos,
        "Brute Force Attack": detect_brute_force,
        "DoS Attack": detect_dos
    }

    for rule_name, rule_func in rules.items():
        execute_rule(rule_name, traffic, rule_func)

# Main function
def main():
    monitor_traffic()

if __name__ == "__main__":
    main()
