from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-ec97489eedeb', filter='icmp', prn=print_pkt) # Sniffing ICMP packets only
