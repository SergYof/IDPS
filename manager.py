import time
from typing import List
from base import Crack
class Manager:
    def start(self, cracks: List[Crack]):
        print("Starting cracks")
        for crack in cracks:
            crack.identify()
        # keep process alive
        while True:
            time.sleep(1)