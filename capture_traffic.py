#capture_traffic.py
import pyshark
from traffic_monitor import TrafficMonitor  # Assuming you have the TrafficMonitor class in traffic_monitor.py

def start_capture(interface="wlp2s0", capture_filter="ip", max_packets=100):
    # Initialize the traffic monitor with the custom packet limit
    monitor = TrafficMonitor(max_packets=max_packets)  

    # Start capturing packets
    print(f"Starting packet capture on {interface}...")
    
    # Use PyShark to capture packets
    capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)
    
    # Set up the packet processing function
    for packet in capture.sniff_continuously():
        monitor.check_packet(packet)  # Process and log the packet

    print("Packet capture stopped.")

if __name__ == "__main__":
    # You can modify the interface here or leave it as the default ("wlp2s0")
    start_capture(interface="wlp2s0", max_packets=100)
