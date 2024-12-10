from datetime import datetime, timedelta
from typing import List, Dict
from alert_system.alert import trigger_alerts

class Rule:
    def __init__(self, name: str, threshold: int, timeframe: int):
        self.name = name
        self.threshold = threshold
        self.timeframe = timeframe
        self.last_check = datetime.now()

class PortScanRule(Rule):
    def __init__(self):
        super().__init__("Port Scan Detection", threshold=10, timeframe=60)
        self.scan_attempts: Dict[str, List[tuple]] = {}

    def check(self, packet):
        src_ip = packet.ip.src
        dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else packet.udp.dstport
        timestamp = datetime.now()

        if src_ip not in self.scan_attempts:
            self.scan_attempts[src_ip] = []

        self.scan_attempts[src_ip].append((dst_port, timestamp))

        # Clean old attempts
        self.scan_attempts[src_ip] = [
            attempt for attempt in self.scan_attempts[src_ip]
            if (timestamp - attempt[1]).seconds <= self.timeframe
        ]

        if len(self.scan_attempts[src_ip]) >= self.threshold:
            trigger_alerts(f"Port Scan detected from {src_ip}")
            return True
        return False

class DDoSRule(Rule):
    def __init__(self):
        super().__init__("DDoS Detection", threshold=1000, timeframe=60)
        self.packet_counts: Dict[str, int] = {}

    def check(self, packet):
        dest_ip = packet.ip.dst
        timestamp = datetime.now()

        if dest_ip not in self.packet_counts:
            self.packet_counts[dest_ip] = 0

        self.packet_counts[dest_ip] += 1

        if self.packet_counts[dest_ip] >= self.threshold:
            trigger_alerts(f"DDoS attack detected on {dest_ip}")
            return True
        return False

class DoSRule(Rule):
    def __init__(self):
        super().__init__("DoS Detection", threshold=500, timeframe=60)
        self.dos_attempts: Dict[str, int] = {}

    def check(self, packet):
        src_ip = packet.ip.src
        timestamp = datetime.now()

        if src_ip not in self.dos_attempts:
            self.dos_attempts[src_ip] = 0

        self.dos_attempts[src_ip] += 1

        if self.dos_attempts[src_ip] >= self.threshold:
            trigger_alerts(f"DoS attack detected from {src_ip}")
            return True
        return False

class BruteForceLoginRule(Rule):
    def __init__(self):
        super().__init__("Brute Force Login Detection", threshold=5, timeframe=60)
        self.failed_logins: Dict[str, List[datetime]] = {}

    def check(self, packet):
        src_ip = packet.ip.src
        timestamp = datetime.now()

        if src_ip not in self.failed_logins:
            self.failed_logins[src_ip] = []

        self.failed_logins[src_ip].append(timestamp)

        # Clean old attempts
        self.failed_logins[src_ip] = [
            attempt for attempt in self.failed_logins[src_ip]
            if (timestamp - attempt).seconds <= self.timeframe
        ]

        if len(self.failed_logins[src_ip]) >= self.threshold:
            trigger_alerts(f"Brute Force Login detected from {src_ip}")
            return True
        return False

class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []
        self.setup_rules()

    def setup_rules(self):
        self.add_rule(PortScanRule())
        self.add_rule(DDoSRule())
        self.add_rule(DoSRule())
        self.add_rule(BruteForceLoginRule())

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def check_packet(self, packet):
        for rule in self.rules:
            if rule.check(packet):
                print(f"Rule triggered: {rule.name}")

