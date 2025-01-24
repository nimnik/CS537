from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-ec97489eedeb', filter='src net 128.230.0.0/16', prn=print_pkt) # Sniffing Packets with their Source IP in 128.230.0.0/16 only