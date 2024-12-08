import logging
from network_traffic_monitor.traffic_monitor import TrafficMonitor
from rule_engine.rule_engine import RuleEngine

# Configure logging
logging.basicConfig(
    filename='./Downloads/intrusion-detection-system-based-on-custom-rules/logs/ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IDSSystem:
    def __init__(self):
        print("[INFO] Initializing IDS System...")
        self.traffic_monitor = TrafficMonitor()
        self.rule_engine = RuleEngine()
        print("[INFO] IDS System initialized successfully.")

    def start(self, verbose=False):
        print(f"\n[INFO] Starting IDS Monitoring in {'Verbose' if verbose else 'Silent'} Mode...")
        self.traffic_monitor.start_capture(
            interface='wlo1', capture_filter='ip', max_packets=100, verbose=verbose
        )

    def stop(self):
        print("[INFO] Stopping IDS Monitoring...")
        self.traffic_monitor.stop()
        print("[SUCCESS] Monitoring stopped.")

class MenuHandler:
    def __init__(self):
        self.ids_system = IDSSystem()

    def display_menu(self):
        print("\n[IDS System Menu]")
        print("1. Start IDS Monitoring")
        print("2. View Current Rules")
        print("3. View Recent Alerts")
        print("4. System Status")
        print("5. Exit")
        return input("Select an option: ").strip()

    def choose_monitoring_mode(self):
        print("\nChoose Monitoring Mode:")
        print("1. Verbose Monitoring (Displays Packets in Real-Time)")
        print("2. Silent Monitoring (No Packet Display)")
        mode = input("Select an option: ").strip()
        return mode == '1'

    def run(self):
        while True:
            choice = self.display_menu()

            if choice == '1':
                verbose = self.choose_monitoring_mode()
                self.ids_system.start(verbose=verbose)
                input("[INFO] Press Enter to stop monitoring...")
                self.ids_system.stop()
            elif choice == '2':
                print("\n[Active Rules]")
                for rule in self.ids_system.rule_engine.rules:
                    print(f"- {rule.name} | Threshold: {rule.threshold}, Timeframe: {rule.timeframe}s")
                input("\nPress Enter to continue...")
            elif choice == '3':
                print("\n[Recent Alerts]")
                for alert in self.ids_system.rule_engine.alerting_system.alerts[-5:]:
                    print(f"- {alert.timestamp}: {alert.alert_type.name} from {alert.source_ip}")
                input("\nPress Enter to continue...")
            elif choice == '4':
                print("\n[System Status]")
                print(f"Monitoring Active: {not self.ids_system.traffic_monitor.capture_stopped}")
                print(f"Rules Loaded: {len(self.ids_system.rule_engine.rules)}")
                print(f"Total Alerts: {len(self.ids_system.rule_engine.alerting_system.alerts)}")
                input("\nPress Enter to continue...")
            elif choice == '5':
                print("\n[INFO] Exiting the system. Goodbye!")
                break
            else:
                print("\n[ERROR] Invalid option. Please try again.")

if __name__ == "__main__":
    menu = MenuHandler()
    menu.run()
