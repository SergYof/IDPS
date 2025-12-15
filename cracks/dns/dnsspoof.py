from ..base import Crack
import scapy.all as scapy

class DNSSpoofCrack(Crack):
  trustedDomains = {
    "google.com": "216.239.38.120", "facebook.com": "157.240.196.35", "ihasabucket.com": "75.119.206.170"}

  def _process_packet(self, packet):
    # checking if the packet is a DNS response
    if packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 1:
      dns_layer = packet.getlayer(scapy.DNS)

      # searching for the A record and decoding domain names
      for i in range(dns_layer.ancount):
        ans = dns_layer.an[i]
        if ans.type == 1:  # A record
          domain = ans.rrname.decode().rstrip('.')
          ip_address = ans.rdata

          # checking decoded domain against trusted domains
          if domain in self.trustedDomains:
            trusted = self.trustedDomains[domain]
            if ip_address != trusted:
              print("[!] DNS Spoofing detected for domain:", domain, "with IP:", ip_address)
          else:
            # unknown domain; flag if IP doesn't match a simple heuristic
            print("[!] DNS response for unknown domain:", domain, "with IP:", ip_address)

  def identify(self):
    # run a short sniff for DNS packets, non-blocking with timeout
    try:
      scapy.sniff(filter="udp port 53", timeout=5, prn=self._process_packet)
    except Exception as e:
      print(f"DNSSpoofCrack sniff error: {e}")