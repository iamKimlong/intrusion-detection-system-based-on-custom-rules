# rules.py

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict
from models import NetworkPacket

class Rule(ABC):
    def __init__(self, name: str, threshold: int, timeframe: int):
        self.name = name
        self.threshold = threshold
        self.timeframe = timeframe
        self.last_check = datetime.now()

    @abstractmethod
    def check(self, packet: NetworkPacket) -> bool:
        pass

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

class DDoSRule(Rule):
    def __init__(self):
        super().__init__("DDoS Detection", threshold=1000, timeframe=60)
        self.packet_counts: Dict[str, int] = {}

    def check(self, packet: NetworkPacket) -> bool:
        dest_ip = packet.dest_ip
        current_time = datetime.now()

        # Initialize or update packet count
        if dest_ip not in self.packet_counts:
            self.packet_counts[dest_ip] = 0

        self.packet_counts[dest_ip] += 1

        # Implement logic to reset counts based on timeframe
        # For simplicity, assume counts are reset externally

        return self.packet_counts[dest_ip] >= self.threshold