from abc import ABC, abstractmethod
from scapy.plist import PacketList


class Crack(ABC):
  def __init__(self, name: str):
    print(f"[!] {name.upper()} STARTED ")


  @abstractmethod
  def identify(self, packetChunk: PacketList) -> list[tuple[str, str, str]]: 
    """Method to defend the crack script"""
    pass