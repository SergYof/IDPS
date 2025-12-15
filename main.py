# from cracks.ARP_Spoofing.arpspoof import ARPSpoofCrack
# from cracks.MITM.mitm import MITMCrack
from cracks.Port_Scanning.portscan import PortScanCrack
from cracks.dns.dnsspoof import DNSSpoofCrack
from manager import Manager

manager = Manager()

def main() -> None:
    manager.persistent(
        intervalSeconds=1,
        cracks=[
            PortScanCrack(),
            DNSSpoofCrack()
        ]
    )


if __name__ == "__main__":
    main()
