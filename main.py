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
    def __init__(self, interface):
        print("[INFO] Initializing IDS System...")
        self.traffic_monitor = TrafficMonitor(interface=interface)
        self.rule_engine = RuleEngine()
        print("[INFO] IDS System initialized successfully.")

    def start(self, verbose=False):
        print("\n[INFO] Starting IDS Monitoring...")
        self.traffic_monitor.start_capture(verbose=verbose)

    def stop(self):
        print("[INFO] Stopping IDS Monitoring...")
        self.traffic_monitor.stop()
        print("[SUCCESS] Monitoring stopped.")

class MenuHandler:
    def __init__(self):
        self.interface = "wlo1"  # Default interface
        self.ids_system = None

    def choose_interface(self):
        print("\nAvailable Network Interfaces (Examples):")
        print("1. wlo1 (Wi-Fi)")
        print("2. eth0 (Ethernet)")
        print("3. Custom Interface")
        choice = input("Select an option: ").strip()

        if choice == '1':
            self.interface = "wlo1"
        elif choice == '2':
            self.interface = "eth0"
        elif choice == '3':
            self.interface = input("Enter your custom interface name: ").strip()
        else:
            print("[ERROR] Invalid selection. Using default interface wlo1.")
            self.interface = "wlo1"

        print(f"[INFO] Using network interface: {self.interface}")
        self.ids_system = IDSSystem(interface=self.interface)

    def run(self):
        self.choose_interface()
        while True:
            print("\n[IDS System Menu]")
            print("1. Start IDS Monitoring")
            print("2. Exit")
            choice = input("Select an option: ").strip()

            if choice == '1':
                verbose = input("Enable verbose mode? (y/n): ").strip().lower() == 'y'
                self.ids_system.start(verbose=verbose)
                input("[INFO] Press Enter to stop monitoring...")
                self.ids_system.stop()
            elif choice == '2':
                print("\n[INFO] Exiting the system. Goodbye!")
                break
            else:
                print("\n[ERROR] Invalid option. Please try again.")

if __name__ == "__main__":
    menu = MenuHandler()
    menu.run()
