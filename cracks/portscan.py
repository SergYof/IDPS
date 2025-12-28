from base import Crack
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import threading
import time

class PortScanCrack(Crack):
    PORT_THRESHOLD = 100
    TIME_WINDOW = 5  # seconds
    def __init__(self):
        self.scans = defaultdict(lambda: {
            "ports": set(),
            "start": time.time()
        })
        self.reported = set()
        self.running = False
    def _process_packet(self, packet):
        if not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        if src_ip in self.reported:
            return
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            return
        entry = self.scans[src_ip]
        entry["ports"].add(port)
        # reset window if expired
        if time.time() - entry["start"] > self.TIME_WINDOW:
            entry["ports"].clear()
            entry["start"] = time.time()
            return
        # detection
        if len(entry["ports"]) >= self.PORT_THRESHOLD:
            print("[!] PORT SCAN DETECTED")
            print(f"    Attacker IP : {src_ip}")
            print(f"    Ports hit   : {sorted(entry['ports'])}")
            self.reported.add(src_ip)
    def _sniff(self):
        sniff(store=False, prn=self._process_packet)
    def identify(self):
        if self.running:
            return
        print("[*] Starting port scan detection...")
        self.running = True
        threading.Thread(target=self._sniff, daemon=True).start()