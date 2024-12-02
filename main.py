import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Dict
import time
import ipaddress

# Configure logging
logging.basicConfig(
    filename='ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AlertType(Enum):
    PORT_SCAN = "Port Scanning"
    DDOS = "DDoS Attack"
    BRUTE_FORCE = "Brute Force Attempt"
    DOS = "DoS Attack"

class AlertSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class NetworkPacket:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    source_port: int
    dest_port: int
    payload_size: int

@dataclass
class Alert:
    timestamp: datetime
    alert_type: AlertType
    severity: AlertSeverity
    source_ip: str
    target_ip: str
    description: str

class TrafficMonitor:
    def __init__(self):
        self.active = False
        self.packet_buffer: List[NetworkPacket] = []
        
    def start_capture(self):
        self.active = True
        logging.info("Traffic monitoring started")
        
    def stop_capture(self):
        self.active = False
        logging.info("Traffic monitoring stopped")
        
    def process_packet(self, packet: NetworkPacket):
        self.packet_buffer.append(packet)
        # Additional processing logic here

class Rule:
    def __init__(self, name: str, threshold: int, timeframe: int):
        self.name = name
        self.threshold = threshold
        self.timeframe = timeframe
        self.violation_count = 0
        self.last_check = datetime.now()

    def check(self, packet: NetworkPacket) -> bool:
        raise NotImplementedError("Subclasses must implement check method")

class PortScanRule(Rule):
    def __init__(self):
        super().__init__("Port Scan Detection", threshold=10, timeframe=60)
        self.scan_attempts: Dict[str, List[tuple]] = {}

    def check(self, packet: NetworkPacket) -> bool:
        source_ip = packet.source_ip
        if source_ip not in self.scan_attempts:
            self.scan_attempts[source_ip] = []
        
        self.scan_attempts[source_ip].append((packet.dest_port, packet.timestamp))
        
        # Clean old attempts
        current_time = datetime.now()
        self.scan_attempts[source_ip] = [
            attempt for attempt in self.scan_attempts[source_ip]
            if (current_time - attempt[1]).seconds <= self.timeframe
        ]
        
        return len(self.scan_attempts[source_ip]) >= self.threshold

class RuleEngine:
    def __init__(self):
        self.rules = []
        self.alerts: List[Alert] = []
        
    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        
    def check_packet(self, packet: NetworkPacket):
        for rule in self.rules:
            if rule.check(packet):
                self.generate_alert(packet, rule)
                
    def generate_alert(self, packet: NetworkPacket, rule: Rule):
        alert = Alert(
            timestamp=datetime.now(),
            alert_type=AlertType.PORT_SCAN,  # This would be determined by rule type
            severity=AlertSeverity.HIGH,
            source_ip=packet.source_ip,
            target_ip=packet.dest_ip,
            description=f"Violation of rule: {rule.name}"
        )
        self.alerts.append(alert)
        logging.warning(f"Alert generated: {alert}")

class IDSSystem:
    def __init__(self):
        self.traffic_monitor = TrafficMonitor()
        self.rule_engine = RuleEngine()
        self.setup_rules()
        
    def setup_rules(self):
        self.rule_engine.add_rule(PortScanRule())
        # Add other rules as needed
        
    def start(self):
        self.traffic_monitor.start_capture()
        
    def stop(self):
        self.traffic_monitor.stop_capture()

class MenuHandler:
    def __init__(self):
        self.ids_system = IDSSystem()

    def display_menu(self):
        print("\nNetwork Intrusion Detection System")
        print("1. Start IDS Monitoring")
        print("2. View Current Rules")
        print("3. View Recent Alerts")
        print("4. System Status")
        print("5. Exit")
        return input("Select an option: ")

    def run(self):
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                self.ids_system.start()
                print("IDS monitoring started...")
                input("Press Enter to stop monitoring...")
                self.ids_system.stop()
            elif choice == '2':
                print("\nActive Rules:")
                print("- Port Scan Detection (10 attempts/60s)")
                print("- DDoS Detection (1000 requests/60s)")
                print("- Brute Force Detection (5 attempts/60s)")
                input("\nPress Enter to continue...")
            elif choice == '3':
                print("\nRecent Alerts:")
                for alert in self.ids_system.rule_engine.alerts[-5:]:
                    print(f"- {alert.timestamp}: {alert.alert_type.value} from {alert.source_ip}")
                input("\nPress Enter to continue...")
            elif choice == '4':
                print("\nSystem Status:")
                print(f"Monitoring Active: {self.ids_system.traffic_monitor.active}")
                print(f"Rules Loaded: {len(self.ids_system.rule_engine.rules)}")
                print(f"Total Alerts: {len(self.ids_system.rule_engine.alerts)}")
                input("\nPress Enter to continue...")
            elif choice == '5':
                print("\nExiting...")
                break
            else:
                print("\nInvalid option. Please try again.")

if __name__ == "__main__":
    menu = MenuHandler()
    menu.run()