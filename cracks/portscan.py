from cracks.base import Crack
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import time
from threading import Lock


class PortScanCrack(Crack):
    PORT_THRESHOLD = 100
    TIME_WINDOW = 5  # seconds

    def __init__(self):
        self.scans = defaultdict(lambda: {
            "ports": set(),
            "start": time.time()
        })
        self.reported = set()
        self.lock = Lock()

    def identify(self, packetChunk):
        now = time.time()

        with self.lock:
            for packet in packetChunk:
                if not packet.haslayer(IP):
                    continue

                src_ip = packet[IP].src

                if src_ip in self.reported:
                    continue

                # Extract destination port
                if packet.haslayer(TCP):
                    port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    port = packet[UDP].dport
                else:
                    continue

                entry = self.scans[src_ip]

                # Reset time window if expired
                if now - entry["start"] > self.TIME_WINDOW:
                    entry["ports"].clear()
                    entry["start"] = now

                entry["ports"].add(port)

                # Detection condition
                if len(entry["ports"]) >= self.PORT_THRESHOLD:
                    print("\n[!] PORT SCAN DETECTED")
                    print(f"    Attacker IP : {src_ip}")
                    print(f"    Ports hit   : {sorted(entry['ports'])}")
                    self.reported.add(src_ip)
