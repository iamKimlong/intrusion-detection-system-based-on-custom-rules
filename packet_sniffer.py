# packet_sniffer.py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from models import NetworkPacket
from threading import Event

class PacketSniffer:
    def __init__(self, config, rule_engine):
        self.rule_engine = rule_engine
        self.interface = config.interface
        self.bpf_filter = config.bpf_filter
        self.stop_sniffing = Event()

    def start(self):
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: self.stop_sniffing.is_set()
        )

    def process_packet(self, packet):
        if IP in packet:
            # Create a NetworkPacket instance
            network_packet = NetworkPacket(
                timestamp=datetime.now(),
                source_ip=packet[IP].src,
                dest_ip=packet[IP].dst,
                protocol=packet[IP].proto,
                source_port=packet[TCP].sport if TCP in packet else 0,
                dest_port=packet[TCP].dport if TCP in packet else 0,
                payload_size=len(packet)
            )
            # Pass the packet to the RuleEngine
            self.rule_engine.check_packet(network_packet)

    def stop(self):
        self.stop_sniffing.set()
