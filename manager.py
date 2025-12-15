from cracks.base import Crack

class Manager:
  def run(self, crack: Crack):
    crack.simulateAttack()
    crack.defend()