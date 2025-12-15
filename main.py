from cracks.base import Crack
from cracks.Port_Scanning.portscan import PortScanCrack
from cracks.ARP_Spoofing.arpspoof import ARPSpoofCrack
from cracks.DNS.dnsspoof import DNSSpoofCrack
from cracks.MITM.mitm import MITMCrack
from time import sleep

# list of classes (NOT objects) of different cracks
ATTACKS: list[type[Crack]] = [PortScanCrack, ARPSpoofCrack, DNSSpoofCrack, MITMCrack]
CHECKS_INTERVAL = 5 # intrval in seconds between different checks


def cycleCracks():
    for attackClass in ATTACKS:
        # TODO: make identify() method in classes static
        attack = attackClass()
        attack.identify()


def main() -> None:
    while True:
        cycleCracks()
        sleep(CHECKS_INTERVAL)
    


if __name__ == "__main__":
    main()