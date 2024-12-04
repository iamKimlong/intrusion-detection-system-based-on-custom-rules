import pyshark
import datetime
import logging

# Configure logging to capture detailed logs of packet captures
logging.basicConfig(
    filename='/home/archuser/Documents/IDS-Project/intrusion-detection-system-based-on-custom-rules/capture_log.txt',
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s'
)

# Get the current timestamp and specify the capture parameters
inter_name = "wlp2s0"  # Name of the network interface to capture (modify as needed)
filename = "/home/archuser/Documents/IDS-Project/intrusion-detection-system-based-on-custom-rules/capture_packets.txt"

# Initialize the packet capture session
capture = pyshark.LiveCapture(interface=inter_name)

# Function to process each captured packet and extract important details
def process_packet(packet, i):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize packet details with timestamp and packet number
    packet_info = f"[{timestamp}] Packet #{i+1}: {packet}\n"
    
    # Extract IP details if available
    if 'IP' in packet:
        packet_info += f"  Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}\n"
    
    # Extract TCP port details if available
    if 'TCP' in packet:
        packet_info += f"  TCP Source Port: {packet.tcp.srcport}, TCP Destination Port: {packet.tcp.dstport}\n"
    
    # Extract UDP port details if available
    if 'UDP' in packet:
        packet_info += f"  UDP Source Port: {packet.udp.srcport}, UDP Destination Port: {packet.udp.dstport}\n"
    
    # Extract DNS query if available
    if 'DNS' in packet:
        packet_info += f"  DNS Query: {packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'N/A'}\n"
    
    # Extract HTTP Host header if available
    if 'HTTP' in packet:
        packet_info += f"  HTTP Host: {packet.http.host if hasattr(packet.http, 'host') else 'N/A'}\n"
    
    return packet_info


# Main function to capture and log packets continuously
def capture_packets():
    try:
        print(f"Process is running... to exit press Ctrl + C.")
        
        # Open the file to append captured packet details
        with open(filename, "a") as file:
            # Continuously capture packets
            for i, packet in enumerate(capture.sniff_continuously()):
                # Process the packet and extract relevant information
                packet_info = process_packet(packet, i)
                
                # Print packet details to the console
                print(packet_info, end="", flush=True)
                
                # Write packet details to the file and flush immediately
                print(f"Writing packet to {filename}: {packet_info}")  # Debug print
                file.write(packet_info)
                file.flush()  # Ensure data is written immediately

                # Optionally, log the packet capture event
                logging.info(f"Captured: {packet_info}")
    
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Capturing has stopped.")
        if 'capture' in locals():
            capture.close()  # Close the capture session
        else:
            print("Capture was not initialized.")

# Execute the capture process when the script runs
if __name__ == "__main__":
    capture_packets()
