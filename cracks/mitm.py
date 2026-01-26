from collections import defaultdict, deque
from time import time
from scapy.layers.l2 import ARP
from cracks.base import Crack

class ARPMitmCrack(Crack):
    # Global detection parameters
    WINDOW = 10              # Time window (seconds)
    MIN_DISTINCT_IPS = 2     # Minimum number of different IPs to raise suspicion

    # Initialize the detector and its internal state
    def __init__(self):
        super().__init__("ARP Man in the Middle")
        self.state = defaultdict(lambda: {
            "claims": deque(),    #(timestamp, IP)
            "alerted": False      # Indicates whether this MAC was already reported
        })

    # Handle every captured network packet
    def on_packet(self, pkt, context):

        # Filter: continue only if this is a valid ARP Reply packet
        if not pkt.haslayer(ARP):
            return []
        arp = pkt[ARP]
        if arp.op != 2:
            return []

        # Extract current time, source MAC and claimed IP
        now = time()
        mac = arp.hwsrc
        ip = arp.psrc

        # Update the claims list for this MAC address
        entry = self.state[mac]
        entry["claims"].append((now, ip))

        # Remove outdated claims outside the time window
        while entry["claims"] and now - entry["claims"][0][0] > self.WINDOW:
            entry["claims"].popleft()

        # Collect all distinct IPs claimed by this MAC
        distinct_ips = {claimed_ip for _, claimed_ip in entry["claims"]}

        # Check attack conditions and trigger alert only once per MAC
        if len(distinct_ips) >= self.MIN_DISTINCT_IPS and not entry["alerted"]:
            entry["alerted"] = True
            context.arp_mitm_macs.add(mac)

            return [(
                "ARP Man in the Middle",
                mac,
                f"MAC {mac} claims multiple IPs: {', '.join(distinct_ips)}"
            )]

        # No attack detected
        return []
