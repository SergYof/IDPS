# IDPS

IDPS is a Python-based network security tool designed to detect common network attacks in real-time. It operates by sniffing network traffic and applying a set of modular detection rules to identify malicious activities.

## Features

*   **Port Scan Detection:** Identifies source IPs scanning a large number of ports, indicating a potential reconnaissance attempt.
*   **ARP Spoofing Detection:** Detects when a device on the network illegitimately claims the IP address of another device by monitoring for conflicting ARP replies.
*   **DNS Spoofing Detection:** Flags suspicious DNS responses by comparing them against a predefined list of trusted domain-to-IP mappings.
*   **Man-in-the-Middle (MITM) Detection:** Identifies potential MITM attacks by tracking changes in the IP-to-MAC address associations observed in ARP traffic.

## How It Works

The system is managed by a central `Manager` that orchestrates the detection process. It operates in a continuous loop:

1.  **Packet Sniffing:** The manager captures a batch of network packets using Scapy.
2.  **Analysis Pipeline:** The captured packets are passed to a series of specialized detection modules (referred to as "Cracks").
3.  **Threat Identification:** Each module analyzes the packets for specific attack signatures.
4.  **Alerting:** If a potential threat is identified, the corresponding module prints an alert to the console with relevant details.

This modular design, based on the abstract `Crack` class, allows for easy extension with new detection capabilities.

## Prerequisites

*   Python 3
*   Scapy library
*   Root or administrator privileges to run the packet sniffer.

## Installation

1.  Clone the repository:
    ```sh
    git clone https://github.com/SergYof/IDPS.git
    cd IDPS
    ```

2.  Install the required Python library:
    ```sh
    pip install scapy
    ```

## Usage

Run the main script with root privileges. The tool will begin sniffing network traffic immediately and will print alerts to the console when a potential attack is detected.

```sh
sudo python3 main.py
```

Example output for a detected ARP spoof:
```
[!] ARP Spoofing detected!
    IP 192.168.1.1 changed from 00:11:22:33:44:55 to AA:BB:CC:DD:EE:FF
```

## Project Structure

```
.
├── LICENSE
├── README.md
├── cracks
│   ├── arpspoof.py      # ARP Spoofing detection logic
│   ├── base.py          # Abstract base class for all detection modules
│   ├── dnsspoof.py      # DNS Spoofing detection logic
│   ├── mitm.py          # MITM detection logic
│   └── portscan.py      # Port Scan detection logic
├── main.py              # Main entry point for the application
└── manager.py           # Orchestrates packet sniffing and analysis
```

## Credits

*   **Port Scanning:** Lev Shapiro
*   **ARP Spoofing:** Adam Greisman
*   **DNS Spoofing:** Ithamar Kaplan & Lior Brezner
*   **MITM:** Yuval Pele Zalmanovich
*   **Code & Software Design:** Sergey Yoffe & Lev Shapiro

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for more details.
