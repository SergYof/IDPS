from .base import Crack
from scapy.layers.l2 import ARP
from scapy.plist import PacketList


class MITMCrack(Crack):    
    def __init__(self):
        super().__init__("MITM")

    def identify(self, packetChunk: PacketList):
        arp_table = {}

        alerts: list[tuple[str, str, str]] = []
        for packet in packetChunk:
            if not (packet.haslayer(ARP) and packet[ARP].op == 2):
                continue
            
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            if ip in arp_table and arp_table[ip] != mac:
                alerts.append(("MITM", f"Suspicious ARP response - MAC mismatch! {ip} was {arp_table[ip]}, but in the response is {mac}", "HIGH"))
            else:
                arp_table[ip] = mac
        
        return alerts