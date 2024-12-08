from loguru import logger
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from plyer import notification
from playsound import playsound
import os
import pyshark  # Import PyShark for packet capturing

    
# Global variable to store user preference 
user_preference = [1]  # Default preference is option 1 (notification with sound)

def get_user_preference():
    # Getter for user's preference
    return user_preference

def set_user_preference(choice):
    # Setter for user's preference
    if choice in [1, 2, 3]:
        user_preference[0] = choice

# Configure logging
logger.add("/log/alerts.log", format="{time} {level} {message}", level="INFO")

# User action storage
flagged_ips = set()
blocked_ips = set()

def send_email(subject, body, recipient_email="recipient@example.com"):
    sender_email = "chhuonnara002@gmail.com"
    app_password = "cnfv uqii avuq anij"

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
        print(f"[EMAIL] Alert sent to {recipient_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def show_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        timeout=20
    )

def play_alert_sound():
    sound_file = "alert.mp3"
    if os.path.exists(sound_file):
        playsound(sound_file)
    else:
        print(f"[ALERT] Sound file '{sound_file}' not found!")

def get_user_action(ip_address, rule_name, details):
    print(f"\n[ALERT] Rule Broken: {rule_name}")
    print(f"[DETAILS] {details}")
    print(f"[IP] Detected from: {ip_address}\n")
    print("Choose an action:")
    print("1. Flag the IP (log only)")
    print("2. Block the IP")
    print("3. Do Nothing")
    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == '1':
        flagged_ips.add(ip_address)
        logger.info(f"IP {ip_address} flagged for breaking rule: {rule_name}")
        print(f"[FLAGGED] IP {ip_address} has been flagged.")
    elif choice == '2':
        blocked_ips.add(ip_address)
        logger.info(f"IP {ip_address} blocked for breaking rule: {rule_name}")
        print(f"[BLOCKED] IP {ip_address} has been blocked.")
    else:
        print("[INFO] No action taken.")

def trigger_alerts(rule_name, ip_address, description, recommended_action="Review the log file."):
    alert_message = (
        f"Rule Broken: {rule_name}\n"
        f"Detected IP: {ip_address}\n"
        f"Details: {description}\n"
        f"Recommended Action: {recommended_action}"
    )

    # Show pop-up notification
    show_notification("Network Security Alert!", alert_message)
    play_alert_sound()

    # Print to terminal and log details
    logger.warning(alert_message)
    get_user_action(ip_address, rule_name, description)