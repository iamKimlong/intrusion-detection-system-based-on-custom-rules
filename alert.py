import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from plyer import notification
from playsound import playsound
import os
import pyshark  # Import PyShark for packet capturing

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
    sender_email = "chhuonnara002@gmail.com"  # Change this to your email
    app_password = "cnfv uqii  avuq anij"  # Use your Gmail app password

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
    sound_file = "alert.mp3"
    if os.path.exists(sound_file):
        playsound(sound_file)
    else:
        print(f"Alert sound file '{sound_file}' not found!")

# Function to capture packets and check for specific conditions
def capture_packets():
    # Modify this based on your desired capture interface or filter
    capture = pyshark.LiveCapture(interface='wlp2s0')  # Example interface; replace with your actual interface

    # Loop through packets
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'ip'):  # Ensure the packet has IP layer
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            description = f"Packet captured: {str(packet)}"  # Use str(packet) instead of packet.summary()

            alert_message = (
                f"Packet captured:\n"
                f"Source IP: {source_ip}\n"
                f"Destination IP: {destination_ip}\n"
                f"Description: {description}"
            )

            trigger_alerts(alert_message, source_ip, destination_ip, description)

# Function to trigger alerts based on the user preference
# Function to trigger alerts automatically
def trigger_alerts(alert_message, source_ip, destination_ip, description):
    global user_preference

    current_default = user_preference[0]
    print(f"Current default option: {current_default}")

    # Trigger alerts based on the user's choice automatically
    if current_default == 1:
        show_notification("Alert!", alert_message)
        play_alert_sound()

    elif current_default == 2:
        recipient_email = "recipient@example.com"  # You can set this to a fixed email or ask for one
        email_subject = "Alert Notification"
        email_body = alert_message
        
        show_notification("Alert!", "Notification sent via email.")
        send_email(email_subject, email_body, recipient_email)

    elif current_default == 3:
        recipient_email = "recipient@example.com"  # You can set this to a fixed email or ask for one
        email_subject = "Alert Notification"
        email_body = alert_message
        
        show_notification("Alert!", "Notification sent via email.")
        play_alert_sound()
        send_email(email_subject, email_body, recipient_email)

# Main function
def main():
    capture_packets()

if __name__ == "__main__":
    main()
