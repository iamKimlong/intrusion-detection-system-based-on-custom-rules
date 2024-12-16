import smtplib
from loguru import logger
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from plyer import notification
import platform
import subprocess
import os

# Global variable to store user preference 
user_preference = [1]  # Default preference is option 1 (notification with sound)

def get_user_preference():
    return user_preference

def set_user_preference(choice):
    if choice in [1, 2, 3]:
        user_preference[0] = choice

# Ensure the logs directory exists
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(log_dir, exist_ok=True)

# Configure the logger with an absolute path
log_file = os.path.join(log_dir, "alerts.log")
logger.add(log_file, format="{time} {level} {message}", level="INFO")

# User action storage
flagged_ips = set()
blocked_ips = set()

def send_email(subject, body, recipient_email="chhuonnara002@gmail.com"):
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
        print(f"[EMAIL] Alert sent to {recipient_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def show_notification(title, message):
    if platform.system() == "Linux":
        try:
            subprocess.run(["notify-send", "--expire-time=10000", "--urgency=critical", title, message], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Notification failed: {e}")
    else:
        notification.notify(
            title=title,
            message=message,
            timeout=20
        )

def play_alert_sound():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    alert_dir = os.path.join(base_dir, "alert_system")
    sound_file = os.path.join(alert_dir, "alert.mp3")

    if os.path.exists(sound_file):
        if platform.system() == "Linux":
            try:
                subprocess.run(["paplay", sound_file], check=True)
            except FileNotFoundError:
                print("[ERROR] 'paplay' not found. Check PulseAudio installation.")
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Sound playback failed: {e}")
        else:
            from playsound import playsound
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
        from network_traffic_monitor.traffic_monitor import RuleEngine  # Avoid circular module calling
        blocked_ips.add(ip_address)
        RuleEngine().known_good_external_ips.add(ip_address)  # Currently, this block function just adds the IP to the ignore list
        logger.info(f"IP {ip_address} blocked for breaking rule: {rule_name}")
        print(f"[BLOCKED] IP {ip_address} has been blocked.")
    else:
        print("[INFO] No action taken.")

def trigger_alerts(rule_name, ip_address, description, recommended_action="Review the log file."):
    alert_message = (
        f"\nRule Broken: {rule_name}\n"
        f"Detected IP: {ip_address}\n"
        f"Details: {description}\n"
        f"Recommended Action: {recommended_action}"
    )

    logger.warning(alert_message)
    show_notification("Network Security Alert!", alert_message)
    play_alert_sound()

    send_email(
        subject="Security Alert: Intrusion Detected",
        body="A suspicious activity was detected on your network. Please review the logs for more details.",
        recipient_email="chhuonnara002@gmail.com"
    )    
    get_user_action(ip_address, rule_name, description)
