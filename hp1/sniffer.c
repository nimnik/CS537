#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

// These two structs are copied from the following website:
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

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
   printf("Got a packet\n");
   char src[100];
   char dst[100];
   // assigining values from captured packet to IP header fields
   const struct sniff_ip *ip;
   ip = (struct sniff_ip*)(packet + 14);

   // Extracting Source and Destination IP addresses
   struct in_addr myip_src = ip->ip_src;
   struct in_addr myip_dst = ip->ip_dst;

   // Convering the IP addresses to dotted format
   strcpy(src, inet_ntoa(myip_src));
   strcpy(dst, inet_ntoa(myip_dst));
   printf("source ip: %s, destination ip: %s\n", src, dst);
}
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp"; // Capturing ICMP packets only
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