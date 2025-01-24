from scapy.all import *
def print_pkt(pkt):
  pkt.show()
pkt = sniff(iface='br-ec97489eedeb', filter='src net 7.8.9.10 and tcp dst port 23', prn=print_pkt) # Sniffing TCP packets with src_ip = 7.8.9.10 and dst_port = 23 only