from .manager import Manager
from .cracks.portscan.portscan import PortScanCrack

manager = Manager()

portscanning = PortScanCrack()

manager.crack(portscanning)