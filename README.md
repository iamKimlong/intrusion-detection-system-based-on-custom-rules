# Network Intrusion Detection System (IDS)

A custom Intrusion Detection System (IDS) developed in Python for detecting network intrusions such as port scans, DDoS attacks, brute-force attempts, and DoS attacks. This IDS provides real-time monitoring, alerting, and logging capabilities, allowing administrators to identify and respond to potential threats effectively.

## Features

- **Real-time Packet Sniffing**: Captures network packets using Scapy.
- **Custom Rule Engine**: Detects suspicious activities based on predefined rules.
- **Alerting System**: Generates alerts (Notification + Sound + Email) for detected intrusions.
- **Menu-Driven Interface**: Allows users to interact with the IDS through a console menu.
- **Logging**: Log all activities inside the ./logs directory.
- **Extensibility**: Easily add new detection rules and alerting mechanisms (inside ./network_traffic_monitor/traffic_monitor.py).
- **Configuration files**: located at ./config/config.py

## Requirements

- Python 3.x
- Administrative privileges (for packet sniffing)
- Python packages: loguru, plyer, playsound, & pyshark.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/iamKimlong/intrusion-detection-system-based-on-custom-rules.git
   ```

2. **Install Required Libraries**

# installing pip for python packages on windows
`Invoke-WebRequest -Uri https://bootstrap.pypa.io/get-pip.py -OutFile get-pip.py`
`py get-pip.py` # py or python or python3...etc

# installing pip for python packages for linux
`sudo pacman -S python-pip` # for arch linux, other OS' tend to be similar

# run this after
`pip install ––upgrade setup-tools wheel pip`
`pip install loguru plyer playsound pyshark`

> **Note:** Depending on your system, you may need to use `pip3` instead of `pip` or even `pipx` for Linux.

3. **Ensure Administrative Privileges**

   Packet sniffing requires root or administrative privileges. Make sure you run the IDS with the necessary permissions.

## Usage

Run the IDS using the following command:

```bash
sudo python3 main.py # for windows

# for linux (if using a virtual environment for python packages)
sudo Downloads/intrusion-detection-system-based-on-custom-rules/venv/bin/python -u Downloads/intrusion-detection-system-based-on-custom-rules/main.py
```

> **Note:** Running as root is necessary for packet sniffing.

## Testing the IDS

To ensure the IDS is functioning correctly, you can simulate attacks using tools like `nmap` `bettercap` `hping3` or `macof`.

### 1. Simulate a Port Scan

Use `nmap` to simulate a port scan:

```bash
nmap -p 1-1000 <target_ip>
```

- Replace `<target_ip>` with the IP address of the machine running the IDS.

### 2. Simulate a DDoS Attack

Use `hping3` to simulate a DDoS attack:

```bash
hping3 --flood -p 80 -S <target_ip>
```

- Ensure `hping3` is installed on your system (`sudo pacman -S hping` on Debian-based systems).
- Replace `<target_ip>` with the IP address of the machine running the IDS.

## Modules Overview

### 1. `main.py`

- Entry point of the application.
- Handles user interaction through the `MenuHandler` class.

### 2. `traffic_monitor.py`
- Monitor all traffics that goes through the network
- Check each packet's source and destination address frequencies within a certain timeframe

### 3. `alert.py`
- Alert through notification, sound, and email

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

---

**Disclaimer:** This IDS is intended for educational purposes and should be used responsibly. Unauthorized network scanning or intrusion detection on networks without permission is illegal and unethical.
