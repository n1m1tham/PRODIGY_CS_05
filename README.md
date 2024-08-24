# Packet Sniffer Tool

This Python packet sniffer tool captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data. **This tool is intended for educational and ethical purposes only.** Unauthorized packet sniffing can violate privacy laws and organizational policies.

## Features

- Captures and displays network packets in real-time.
- Provides information on source and destination IP addresses.
- Identifies TCP and UDP protocols and displays the corresponding ports.
- Displays the raw payload data when available.

## Installation

### Prerequisites

- **Python 3.x**: Ensure Python 3 is installed on your system.
- **scapy**: Install the `scapy` library, which is used for packet manipulation and analysis.

### Installing `scapy`

Use pip to install the `scapy` library:
   
   ```bash
   pip3 install scapy
   ```
Clone the Repository:
   
   ```bash
   git clone https://github.com/your-username/PRODIGY_CS_05.git
   cd PRODIGY_CS_05
   ```
The script must be run with elevated privileges to access the network interface:
   ```bash
   sudo python3 packet_sniffer.py
   ```

