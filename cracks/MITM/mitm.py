from ..base import Crack
from scapy.all import sniff, ARP

class MIDMCrack(Crack):
    arp_table = {}  #stores IP, MAC mapping

    def identify(self):
        def detect(packet):
            #check if packet is ARP reply
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                ip = packet[ARP].psrc    #claimed source IP
                mac = packet[ARP].hwsrc  #source MAC address

                #if IP was seen before with different MAC then "Man In The Middle"
                if ip in self.arp_table and self.arp_table[ip] != mac:
                    print("MITM DETECTED")
                    print(ip, self.arp_table[ip], mac)
                else:
                    #learn normal IP-MAC mapping
                    self.arp_table[ip] = mac

        #listen only to ARP traffic
        sniff(filter="arp", store=False, prn=detect)
