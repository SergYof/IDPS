from abc import ABC, abstractmethod

class Crack(ABC):
  @abstractmethod
  def run(): 
    """Method to run the crack script"""
    pass