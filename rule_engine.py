# rule_engine.py

from models import Alert, AlertType, AlertSeverity, NetworkPacket
from alerting import AlertingSystem
from rules import Rule, PortScanRule
from datetime import datetime
from typing import List

class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []
        self.alerting_system = AlertingSystem()
        self.setup_rules()
    
    def setup_rules(self):
        self.add_rule(PortScanRule())
        # Add other rules as needed

    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        
    # rule_engine.py (in setup_rules method)

    def setup_rules(self):
        self.add_rule(PortScanRule())
        self.add_rule(DDoSRule())
        # Add other rules as needed

    
    def check_packet(self, packet: NetworkPacket):
        for rule in self.rules:
            if rule.check(packet):
                self.generate_alert(packet, rule)
                
    def generate_alert(self, packet: NetworkPacket, rule: Rule):
        alert_type = AlertType.PORT_SCAN  # Determine based on the rule
        alert = Alert(
            timestamp=datetime.now(),
            alert_type=alert_type,
            severity=AlertSeverity.HIGH,
            source_ip=packet.source_ip,
            target_ip=packet.dest_ip,
            description=f"Violation of rule: {rule.name}"
        )
        self.alerting_system.send_alert(alert)
