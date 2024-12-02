# traffic_monitor.py

import logging
from typing import List
from models import NetworkPacket

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
