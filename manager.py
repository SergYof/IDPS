import time
from cracks.base import Crack

class Manager:
  def one(self, crack: Crack):
    return crack.identify()
  
  def pipe(self, cracks: list[Crack]):
    for crack in cracks:
      try:
        crack.identify()
      except Exception as e:
        print(f"Error in {crack.__class__.__name__}: {e}")
      
  def persistent(self, intervalSeconds: int, cracks: list[Crack]):
    while True:
      print("Identifying cracks", flush=True)
      self.pipe(cracks)
      time.sleep(intervalSeconds)
  