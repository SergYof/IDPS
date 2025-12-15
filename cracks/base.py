from abc import ABC, abstractmethod

class Crack(ABC):
  @abstractmethod
  def defend(self): 
    """Method to defend the crack script"""
    pass