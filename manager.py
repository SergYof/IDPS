from cracks.crack import Crack

class Manager:
  def run(self, crack: Crack):
    crack.attack()
    crack.defend()