import pyshark

# Specify the network interface to capture traffic on (replace 'wlp2s0' with your interface)
interface = 'wlp2s0'

print("Starting capture... Press Ctrl+C to stop.")

try:
    capture = pyshark.LiveCapture(interface=interface)
    
    # Capture 5 packets
    for packet in capture.sniff_continuously(packet_count=5):
        print(f"Packet: {packet}")  # Print the entire packet
        
        # You can print layers for more detailed information
        for layer in packet:
            print(f"Layer: {layer.layer_name}, Info: {layer}")
            
        # Alternatively, you can print the highest layer (IP, TCP, etc.)
        print(f"Highest Layer: {packet.highest_layer}")
        
except KeyboardInterrupt:
    print("Capture stopped.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Ensure capture.close() is only called if the capture object was successfully created
    if 'capture' in locals():
        capture.close()
    else:
        print("Capture was not initialized.")
