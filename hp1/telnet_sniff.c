#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

// These three structs are copied from the following website:
// https://www.tcpdump.org/pcap.html

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
   printf("Got a packet\n");
   char src[100];
   char dst[100];
   const struct sniff_ip *ip;
   const struct sniff_tcp *tcp;
   const char *payload;

   // assigining values from captured packet to IP header fields
   ip = (struct sniff_ip*)(packet + 14);

   // Extracting Source and Destination IP addresses
   struct in_addr myip_src = ip->ip_src;
   struct in_addr myip_dst = ip->ip_dst;

   // Convering the IP addresses to dotted format
   strcpy(src, inet_ntoa(myip_src));
   strcpy(dst, inet_ntoa(myip_dst));

   // assigining values from captured packet to TCP header fields
   u_int size_ip = IP_HL(ip)*4;
   tcp = (struct sniff_tcp*)(packet + 14 + size_ip);

   // Extracting Source and Destination TCP ports
   uint16_t tcp_src = ntohs(tcp->th_sport);
   uint16_t tcp_dst = ntohs(tcp->th_dport);

   // Assigining values from captured packet to the datastucture holding Paylod and Extracting the Payload
   u_int size_tcp = TH_OFF(tcp)*4;
   payload = (u_char *)(packet + 14 + size_ip + size_tcp);

   printf("payload: %s\n", payload);

}
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // Capturing TCP packets only
  bpf_u_int32 net;
  // Step 1: Open live pcap session on NIC with name eth3.
  //         Students need to change "eth3" to the name found on their own
  //         machines (using ifconfig). The interface to the 10.9.0.0/24
  //         network has a prefix "br-" (if the container setup is used).
  handle = pcap_open_live("br-511800915c48", BUFSIZ, 1, 1000, errbuf);
  printf("Works without root privilege.\n");
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  printf("Works without root privilege?\n");
  if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);   //Close the handle
  return 0;
}