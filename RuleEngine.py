from alert import AlertHandler

# Predefined rules for simple attacks
predefined_rules = [
    {"name": "Port Scan Detection", "type": "port_scan", "threshold": 10},
    {"name": "DDoS Detection", "type": "ddos", "threshold": 100}
]

def load_rules_from_config(filename):
    """Load additional rules from a configuration file."""
    rules = []
    with open(filename, "r") as file:
        for line in file:
            parts = line.strip().split(", ")
            if len(parts) == 3:
                rules.append({"name": parts[0], "type": parts[1], "threshold": int(parts[2])})
    return rules

def check_packet(packet_summary, rules):
    """Check if the packet matches any rule."""
    for rule in rules:
        if rule["type"] == "port_scan" and packet_summary.get("src_ip"):
            print(f"Port scan detected from {packet_summary['src_ip']}")
            # Trigger alert logic if needed (like email, popup)
            AlertHandler().trigger_alert(f"Port scan detected from {packet_summary['src_ip']}!")
        elif rule["type"] == "ddos" and packet_summary.get("dst_ip"):
            print(f"DDoS attack detected against {packet_summary['dst_ip']}")
            AlertHandler().trigger_alert(f"DDoS attack detected against {packet_summary['dst_ip']}!")
