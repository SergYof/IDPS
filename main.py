from cracks.base import Crack
from cracks.Port_Scanning.portscan import PortScanCrack
from cracks.ARP_Spoofing.arpspoof import ARPSpoofCrack
from cracks.dns.dnsspoof import DNSSpoofCrack
from cracks.MITM.mitm import MITMCrack
from time import sleep

ATTACKS: list[type[Crack]] = [PortScanCrack, ARPSpoofCrack, DNSSpoofCrack, MITMCrack]
CHECKS_INTERVAL = 5

def cycleCracks():
    for attackClass in ATTACKS:
        attack = attackClass()
        attack.identify()


def main() -> None:
    while True:
        cycleCracks()
        sleep(CHECKS_INTERVAL)
    


if __name__ == "__main__":
    main()