from abc import ABC, abstractmethod

class Crack(ABC):
  @abstractmethod
  def simulateAttack(self): 
    """Method to attack the crack script"""
    pass

  @abstractmethod
  def defend(self): 
    """Method to defend the crack script"""
    pass