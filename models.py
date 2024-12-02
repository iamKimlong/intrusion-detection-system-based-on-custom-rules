# models.py

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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
