from scapy.sendrecv import sniff
from time import time
import logging

from bus.alert_bus import ALERT_BUS
from bus.packet_bus import PACKET_BUS
from context import Context

# Suppress Scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Manager:
    def __init__(self, cracks):
        self.cracks = cracks
        self.context = Context()  # Shared context

    def process_packet(self, pkt):
        suspicious = False

        for crack in self.cracks:
            alerts = crack.on_packet(pkt, self.context)

            for alert in alerts:
                suspicious = True
                self._publish_alert(crack, alert)

        PACKET_BUS.publish(pkt, suspicious=suspicious)

    def _publish_alert(self, crack, alert):
        attack, attacker, details = alert

        ALERT_BUS.publish({
            "attack": attack,
            "time": time(),
            "attacker": attacker,
            "victim": "N/A",
            "details": details
        })

    def start(self):
        sniff(
            prn=self.process_packet,
            store=False,
            promisc=True
        )