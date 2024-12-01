# Test writing to the file
filename = "/home/archuser/Documents/IDS-Project/intrusion-detection-system-based-on-custom-rules/capture_packets.txt"

try:
    with open(filename, "a") as file:  # Append mode
        file.write("Test message\n")
        file.flush()  # Ensure data is written immediately
    print("Test message written successfully.")
except Exception as e:
    print(f"Error writing to file: {e}")
