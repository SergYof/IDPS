from base import Crack
from scapy.layers.dns import DNS, UDP
import dns.resolver  # Import the DNS resolver library


class DNSSpoofCrack(Crack):
    def __init__(self):
        super().__init__("DNS Spoofing")

        # Configure a resolver to use a Trusted DNS Server (e.g., Google 8.8.8.8)
        # This bypasses your local network's potentially poisoned DNS cache.
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def identify(self):
        for packet in self.packets:
            # Check for UDP port 53
            if not packet.haslayer(UDP) or packet[UDP].dport != 53:
                continue

            # Check if it is a DNS Response (qr == 1)
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                dns_layer = packet[DNS]

                for i in range(dns_layer.ancount):
                    ans = dns_layer.an[i]

                    # Type 1 is an 'A' record (IPv4)
                    if ans.type == 1:
                        domain = ans.rrname.decode().rstrip('.')
                        captured_ip = ans.rdata

                        # Perform the dynamic check
                        self.verify_dynamic(domain, captured_ip)

    def verify_dynamic(self, domain, captured_ip):
        """
        Queries a trusted DNS server for the domain and compares the result
        with the captured packet's IP.
        """
        try:
            # Query the trusted nameserver for the real IPs
            answers = self.resolver.resolve(domain, 'A')
            trusted_ips = [r.to_text() for r in answers]

            # Check if the captured IP exists in the list of trusted IPs
            if captured_ip not in trusted_ips:
                print(f"[!] POTENTIAL SPOOF: {domain}")
                print(f"    Packet IP: {captured_ip}")
                print(f"    Trusted IPs: {trusted_ips}")
            else:
                # Optional: specific verbose logging for valid packets
                # print(f"[+] Verified Valid: {domain} -> {captured_ip}")
                pass

        except dns.resolver.NXDOMAIN:
            print(f"[!] Domain does not exist (NXDOMAIN): {domain}")
        except dns.exception.Timeout:
            print(f"[?] Timeout verifying {domain}")
        except Exception as e:
            print(f"[?] Error verifying {domain}: {e}")