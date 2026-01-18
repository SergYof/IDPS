from collections import defaultdict, deque
from time import time
from scapy.layers.l2 import ARP
from base import Crack


class ARPMitmCrack(Crack):
    WINDOW = 10
    MIN_DISTINCT_IPS = 2

    def __init__(self):
        super().__init__("ARP Man in the Middle")
        self.state = defaultdict(lambda: {
            "claims": deque(),
            "alerted": False
        })

    def on_packet(self, pkt, context):
        if not pkt.haslayer(ARP):
            return []

        arp = pkt[ARP]
        if arp.op != 2:
            return []

        now = time()
        mac = arp.hwsrc
        ip = arp.psrc

        entry = self.state[mac]
        entry["claims"].append((now, ip))

        while entry["claims"] and now - entry["claims"][0][0] > self.WINDOW:
            entry["claims"].popleft()

        distinct_ips = {claimed_ip for _, claimed_ip in entry["claims"]}

        if len(distinct_ips) >= self.MIN_DISTINCT_IPS and not entry["alerted"]:
            entry["alerted"] = True
            context.arp_mitm_macs.add(mac)

            return [(
                "ARP Man in the Middle",
                mac,
                f"MAC {mac} claims multiple IPs: {', '.join(distinct_ips)}"
            )]

        return []
