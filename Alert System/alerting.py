# alerting.py

from loguru import logger
from models import Alert

class AlertingSystem:
    def __init__(self):
        self.alerts = []

    def send_alert(self, alert: Alert):
        # Log the alert
        logger.warning(f"Alert generated: {alert}")
        self.alerts.append(alert)
        # Additional alerting mechanisms (e.g., email) can be added here
