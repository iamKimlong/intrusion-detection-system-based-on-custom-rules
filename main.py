# main.py

import logging
from ids_system import IDSSystem

# Configure logging
logging.basicConfig(
    filename='ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class MenuHandler:
    def __init__(self):
        self.ids_system = IDSSystem()

    def display_menu(self):
        print("\nNetwork Intrusion Detection System")
        print("1. Start IDS Monitoring")
        print("2. View Current Rules")
        print("3. View Recent Alerts")
        print("4. System Status")
        print("5. Exit")
        return input("Select an option: ")

    def run(self):
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                self.ids_system.start()
                print("IDS monitoring started...")
                input("Press Enter to stop monitoring...")
                self.ids_system.stop()
            elif choice == '2':
                print("\nActive Rules:")
                for rule in self.ids_system.rule_engine.rules:
                    print(f"- {rule.name} ({rule.threshold} attempts/{rule.timeframe}s)")
                input("\nPress Enter to continue...")
            elif choice == '3':
                print("\nRecent Alerts:")
                for alert in self.ids_system.rule_engine.alerting_system.alerts[-5:]:
                    print(f"- {alert.timestamp}: {alert.alert_type.value} from {alert.source_ip}")
                input("\nPress Enter to continue...")
            elif choice == '4':
                print("\nSystem Status:")
                print(f"Monitoring Active: {self.ids_system.traffic_monitor.active}")
                print(f"Rules Loaded: {len(self.ids_system.rule_engine.rules)}")
                print(f"Total Alerts: {len(self.ids_system.rule_engine.alerting_system.alerts)}")
                input("\nPress Enter to continue...")
            elif choice == '5':
                print("\nExiting...")
                break
            else:
                print("\nInvalid option. Please try again.")

if __name__ == "__main__":
    menu = MenuHandler()
    menu.run()
