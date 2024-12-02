# ids_system.py

from packet_sniffer import PacketSniffer
from rule_engine import RuleEngine
from traffic_monitor import TrafficMonitor
from config import Config
import threading

class IDSSystem:
    def __init__(self):
        self.config = Config()
        self.rule_engine = RuleEngine()
        self.traffic_monitor = TrafficMonitor()
        self.packet_sniffer = PacketSniffer(self.config, self.rule_engine)
        self.sniffer_thread = None
    
    def start(self):
        self.traffic_monitor.start_capture()
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer.start)
        self.sniffer_thread.start()
        
    def stop(self):
        self.traffic_monitor.stop_capture()
        self.packet_sniffer.stop()
        self.sniffer_thread.join()
