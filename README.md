
# IDS: Intrusion Detection System

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## What is IDS?

**IDS** is a lightweight, extensible network intrusion detection system featuring a live GUI, modular detection engine, and real-time alerting. It is designed for rapid prototyping, educational use, and easy extension with new detection modules ("cracks").

---

## Key Features & Benefits

- **Live network monitoring** with a modern Tkinter GUI ([gui.py](gui.py))
- **Multiple built-in detectors**:
  - Port scan detection ([cracks/portscan.py](cracks/portscan.py))
  - ARP spoof/mitm detection ([cracks/arpspoof.py](cracks/arpspoof.py))
  - DNS spoof detection ([cracks/dnsspoof.py](cracks/dnsspoof.py))
- **Modular "crack" interface** for easy extension ([cracks/base.py](cracks/base.py))
- **Flow tracking and expiry** ([engine/flow_manager.py](engine/flow_manager.py), [engine/flow.py](engine/flow.py))
- **In-process buses** for packets and alerts ([bus/packet_bus.py](bus/packet_bus.py), [bus/alert_bus.py](bus/alert_bus.py))
- **GeoIP lookup** support ([utils/geoip.py](utils/geoip.py))
- **Small, readable codebase** for learning and experimentation

---

## Getting Started

### Prerequisites

- Python 3.8+ (Windows recommended; Linux/macOS may work)
- Administrative privileges (for packet capture)
- [Npcap](https://nmap.org/npcap/) (Windows) or equivalent packet capture driver

### Installation

1. Install dependencies:
	```sh
	python -m pip install scapy geoip2
	```
2. (Optional) For GeoIP support, download the MaxMind GeoLite2-City.mmdb and place it in the project root or update [utils/geoip.py](utils/geoip.py) to your DB path.

### Configuration

- Edit the capture interface in [main.py](main.py) if needed (see the `IFACE` constant or interface selection logic).

### Usage

Start the application:

```sh
python main.py
```

The GUI will launch automatically, displaying live alerts and packet streams. Alerts are published to the GUI via [bus/alert_bus.py](bus/alert_bus.py).

---

## Example: Adding a New Detector

To add your own detection module, subclass `Crack` from [cracks/base.py](cracks/base.py) and implement the `on_packet` or `on_flow` methods. See [cracks/arpspoof.py](cracks/arpspoof.py) or [cracks/portscan.py](cracks/portscan.py) for examples.

---

## Support & Documentation

- For help, open an issue or discussion in this repository.
- See code comments and docstrings for in-line documentation.
- For advanced usage or troubleshooting, see the [wiki](docs/).

---

*This project is for educational and research purposes. Use responsibly and only on networks you own or have permission to monitor.*
- Packet processing and detection are in `manager.py` and detectors in `cracks/`.
- The project uses Scapy for packet parsing. On Windows, install Npcap (https://nmap.org/npcap/) and run Python with administrator privileges to capture packets.

## Project tree

- [README.md](README.md)
- [main.py](main.py)
- [manager.py](manager.py)
- [context.py](context.py)
- [gui.py](gui.py)

- bus/
	- [alert_bus.py](bus/alert_bus.py)
	- [packet_bus.py](bus/packet_bus.py)
- cracks/
	- [base.py](cracks/base.py)
	- [portscan.py](cracks/portscan.py)
	- [arpspoof.py](cracks/arpspoof.py)
	- [dnsspoof.py](cracks/dnsspoof.py)
	- [mitm.py](cracks/mitm.py)
- engine/
	- [flow_manager.py](engine/flow_manager.py)
	- [flow.py](engine/flow.py)
- utils/
	- [geoip.py](utils/geoip.py)
