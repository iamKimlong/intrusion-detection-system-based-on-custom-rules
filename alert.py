#alert 

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from plyer import notification
from playsound import playsound
from scapy.all import sniff, IP
import os

# Global variable to store user preference (default is option 1 - notification with sound)
user_preference = [1]  # Default preference is option 1 (notification with sound)

def get_user_preference():
    """Getter for user_preference."""
    return user_preference
    

def set_user_preference(choice):
    """Setter for user_preference."""
    if choice in [1, 2, 3]:
        user_preference[0] = choice


# Function to send an email
def send_email(subject, body, recipient_email):
    sender_email = "user28379362@gmail.com"  # Change this to your email
    app_password = "bhhi xspb wyds shiw"  # Use your Gmail app password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"Email sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to show a notification
def show_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        app_icon=None,
        timeout=20
    )

# Function to play an alert sound
def play_alert_sound():
    sound_file = "C:/Users/Loch Thida/OneDrive/Documents/CADT-YEAR02/TERM1/Python in Cyber/project/intrusion-detection-system-based-on-custom-rules/alert2 (online-audio-converter.com).mp3"
    if os.path.exists(sound_file):
        playsound(sound_file)
    else:
        print(f"Alert sound file '{sound_file}' not found!")

# Function to process a network packet and extract IP details
def process_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        description = f"Packet captured: {source_ip} -> {destination_ip}"
        return source_ip, destination_ip, description
    else:
        return None, None, "Non-IP packet detected"
    
# Function to capture network traffic
def capture_traffic():
    packet = sniff(count=1)[0]
    return process_packet(packet)

# Function to count lines in the alert log file
def count_log_lines(log_file_path):
    # Ensure the log file exists before counting
    if not os.path.exists(log_file_path):
        return 0
    with open(log_file_path, 'r') as log_file:
        return len(log_file.readlines())

# Function to create the alert.log file if it doesn't exist (without creating the log folder)
def ensure_log_file(log_file_path):
    # Only check if the log file exists, assume the folder is already there
    if not os.path.exists(log_file_path):
        with open(log_file_path, 'w') as log_file:
            log_file.write("")  # Create an empty log file

# Main function
def main():
    global user_preference
    log_file_path = "C:/Users/Loch Thida/OneDrive/Documents/CADT-YEAR02/TERM1/Python in Cyber/project/intrusion-detection-system-based-on-custom-rules/logs/alert.log"  # Path to the alert log file

    # Ensure the log file exists
    ensure_log_file(log_file_path)

    # Capture real network data
    source_ip, destination_ip, description = capture_traffic()

    if not source_ip or not destination_ip:
        print("No valid IP packet detected. Exiting.")
        return

    current_default = user_preference[0]
    print(f"Current default option: {current_default}")
    print("Choose an option:")
    print("1. Show notification and play alert sound")
    print("2. Show notification and send email (no sound)")
    print("3. Show notification, play alert sound, and send email (Log info included)")
    
    # Allow user to input choice
    choice = input("Enter your choice (1, 2, or 3, or press Enter to use default): ")

    # Validate choice
    if choice not in ['1', '2', '3', '']:
        print("Invalid choice. Exiting.")
        return

    # Use default option if no input is provided
    if choice == '':
        choice = str(current_default)
    else:
        # Update default option for future runs (for this session only)
        user_preference[0] = int(choice)

    alert_message = (
        f"Alert! Rule violation detected.\n"
        f"Source IP: {source_ip}\n"
        f"Destination IP: {destination_ip}\n"
        f"Description: {description}"
    )

    # Trigger alerts based on the user's choice
    if choice == '1':
        show_notification("Alert!", alert_message)
        play_alert_sound()

    elif choice == '2':
        recipient_email = input("Enter the recipient email address: ")
        email_subject = "Alert Notification"
        email_body = alert_message
        
        show_notification("Alert!", "Notification sent via email.")
        send_email(email_subject, email_body, recipient_email)

    elif choice == '3':
        recipient_email = input("Enter the recipient email address: ")
        email_subject = "Alert Notification"

        # Count the number of lines in the log file
        log_lines_count = count_log_lines(log_file_path)
        
        # Add log info to the email body
        email_body = (
            f"{alert_message}\n"
            f"Log entries in {log_file_path}: {log_lines_count} entries found."
        )
        
        show_notification("Alert!", f"Notification sent via email. Log entries: {log_lines_count}")
        play_alert_sound()
        send_email(email_subject, email_body, recipient_email)

if __name__ == "__main__":
    main()

