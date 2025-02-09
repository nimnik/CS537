from scapy.all import *

# Printing Payload of TCP packets
def print_pkt(pkt):

    if pkt[TCP].payload:
    
        data = pkt[TCP].payload.load
        print(f"Length: {len(data)}, Payload: {data}")


f = 'tcp' # Only Capture TCP packets
pkt = sniff(iface='eth0', filter=f, prn=print_pkt)