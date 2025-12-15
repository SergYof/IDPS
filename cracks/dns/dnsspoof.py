from ..base import Crack
import scapy.all as scapy

class DNSSpoofCrack(Crack):
  trustedDomains = {
    "google.com": "216.239.38.120", "facebook.com": "157.240.196.35", "ihasabucket.com": "75.119.206.170"}
  
  def identify(self, packet):
    #checking if the packet is a DNS response
    if packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 1:
      dns_layer = packet.getlayer(scapy.DNS)
      
      for i in range(dns_layer.ancount):
        ans = dns_layer.an[i]
        if ans.type == 1:  # A record
          domain = ans.rrname.decode().rstrip('.')
          ip_address = ans.rdata
          
          if domain not in self.trustedDomains and ip_address != self.trustedDomains[domain]:
            print("[!] DNS Spoofing detected for domain:", domain, "with IP:", ip_address)