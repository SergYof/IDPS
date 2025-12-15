from ..base import Crack
from scapy.all import sniff, TCP, UDP, IP

class PortScanCrack(Crack):
  store = {}

  def identify(self):
    self.store = {}
    packets = sniff(count=2000, timeout=3)

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        src_ip = packet[IP].src

        isTCP = packet.haslayer(TCP)
        isUDP = packet.haslayer(UDP)

        if not (isTCP or isUDP):
            continue

        if src_ip not in self.store:
            self.store[src_ip] = {}

        port = packet[TCP].dport if isTCP else packet[UDP].dport
        self.store[src_ip][port] = True

    return sorted([k for k, v in self.store.items() if len(v) >= 2000])