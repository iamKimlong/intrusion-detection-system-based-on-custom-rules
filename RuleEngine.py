#rule_engine

import logging
import os
from alert import main as trigger_alert  # Only call the main alert function

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
    """
    Detects brute force attacks by monitoring repeated failed authentication attempts
    from the same source IP.
    """
    failed_attempts = {}
    for packet in traffic:
        source_ip = packet.get("source_ip")
        status = packet.get("auth_status", "success")  # Simulate an "auth_status" field
        if source_ip and status == "failure":
            failed_attempts[source_ip] = failed_attempts.get(source_ip, 0) + 1
    return any(count > 5 for count in failed_attempts.values())

def detect_dos(traffic):
    """Detects DoS attacks by monitoring high traffic volume from a single source IP."""
    source_count = {}
    for packet in traffic:
        source_ip = packet.get("source_ip")
        if source_ip:
            source_count[source_ip] = source_count.get(source_ip, 0) + 1
    return any(count > 40 for count in source_count.values())

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
def execute_rule(rule_name, traffic, rule_function):
    """Executes the selected rule, logs the result, and triggers an alert call if detected."""
    log_file = setup_logging(rule_name)
    logging.info(f"Monitoring traffic with rule: {rule_name}")
    
    if rule_function(traffic):
        logging.info(f"{rule_name} detected!")
        print(f"Alert: {rule_name} detected! Check the log file: {log_file}")

        # Call the alert system (handled in alert.py)
        trigger_alert()  # Calls the main function in alert.py for sending alerts
    else:
        print(f"No issues detected for rule: {rule_name}.")

# Main function
def main():
    print("Select the rule to monitor:")
    rules = {
        "1": ("Port Scanning", detect_port_scanning),
        "2": ("DDoS Attack", detect_ddos),
        "3": ("Brute Force Attack", detect_brute_force),
        "4": ("DoS Attack", detect_dos),
    }

    for key, (name, _) in rules.items():
        print(f"{key}. {name}")

    choice = input("Enter your choice (1/2/3/4): ")
    if choice in rules:
        rule_name, rule_function = rules[choice]
        # Replace 'traffic' with the actual traffic data provided to the system.
        traffic = []  # Placeholder for real traffic data
        execute_rule(rule_name, traffic, rule_function)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
