# IDS — Intrusion Detection System
Lightweight, extensible network intrusion monitoring with live GUI, multiple detector "cracks" (PortScan, ARP spoof, DNS spoof).

**Key features**
- Port-scan detection (`cracks/portscan.py`)
- ARP spoof/mitm detection (`cracks/arpspoof.py`)
- DNS spoof detection (`cracks/dnsspoof.py`)
- Flow tracking and expiry (`engine/flow_manager.py`, `engine/flow.py`)
- Live Tkinter GUI for alerts and packet stream (`gui.py`)
- Simple in-process buses for packets and alerts (`bus/packet_bus.py`, `bus/alert_bus.py`)
- Optional GeoIP lookup when `GeoLite2-City.mmdb` is available (`utils/geoip.py`)

Why this project is useful
- Small, easy-to-read codebase for learning IDS concepts and rapid prototyping
- Modular "crack" detector interface (`cracks/base.py`) — add new detection modules easily
- GUI + in-memory buses make it simple to experiment with different visualizations or sinks

Quick start

Prerequisites
- Python 3.8+ on Windows (Linux/macOS may work; Windows-specific interface handling is included)
- Administrative privileges / packet capture driver (Npcap recommended on Windows)
- Install Python packages:

```powershell
python -m pip install scapy geoip2
```

If you plan to use GeoIP lookup, download the MaxMind GeoLite2-City.mmdb and place it next to the repo or update `utils/geoip.py` to point to your DB path.

Run
- Configure the capture interface in `main.py` by editing the `IFACE` constant (Windows: NPF interface name). See [main.py](main.py).
- Start the app:

```powershell
python main.py
```

Notes
- The GUI starts automatically in a background thread; alerts are published to the GUI via `bus/alert_bus.py`.
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
- engine/
	- [flow_manager.py](engine/flow_manager.py)
	- [flow.py](engine/flow.py)
- utils/
	- [geoip.py](utils/geoip.py)
