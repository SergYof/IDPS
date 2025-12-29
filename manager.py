from typing import List
from cracks.base import Crack
from scapy.plist import PacketList
from scapy.sendrecv import sniff
from threading import Thread
from IDS import IDPSGui

ATTACK_CHECK_INTERVAL = 5   # how frequently the chunks are scanned  

class Manager:
    gui: IDPSGui # GUI object
    
    def __init__(self):
        self.gui = IDPSGui() 
        self.gui.run()


    def runOnce(self, crack: Crack, packetChunk: PacketList):   # check one packet chunk for one crack type
        alertList = crack.identify(packetChunk)  # get the list of all alerts
        for alert in alertList:
            self.gui.add_alert(*alert)  # every alert is a tuple of 3 strings


    def start(self, cracks: List[Crack]):
        # keep running
        while True:
            print("Sniffing packets")
            packetLst = sniff(timeout=ATTACK_CHECK_INTERVAL, quiet=True)    # sniff for some time
            
            threadList: list[Thread] = []
            for crack in cracks:    # launch parallel crack checking
                threadList.append(Thread(target=self.runOnce, args=(crack, packetLst)))
                threadList[-1].run()
            
            for t in threadList:    # stop the checks
                t.join()
            
            # the results must be outputted by the functions
            # this is done inside the threads, so no need to do it here

