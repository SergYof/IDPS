from abc import ABC, abstractmethod

class Crack(ABC):
  @abstractmethod
  def attack(self): 
    """Method to attack the crack script"""
    pass

  @abstractmethod
  def defend(self): 
    """Method to defent the crack script"""
    pass