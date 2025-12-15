from ..base import Crack
from scapy.all import *

class PortScanCrack(Crack):
  TARGET_IP = "192.168.1.1"
  PORT_FROM = 0
  PORT_TO = 65535

  def defend(self):
    pass
  
  