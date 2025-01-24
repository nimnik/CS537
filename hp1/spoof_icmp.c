#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

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


int main(){

    int sd;
    struct sockaddr_in sin;
    char buffer[2048]; // You can change the buffer size
    /* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
    * tells the sytem that the IP header is already included;
    * this prevents the OS from adding another IP header.  */
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error"); exit(-1);
    }
    /* This data structure is needed when sending the packets
    * using sockets. Normally, we need to fill out several
    * fields, but for raw sockets, we only need to fill out
    * this one field */
    sin.sin_family = AF_INET;
    inet_aton("10.9.0.5", &(sin.sin_addr));
    // Here you can construct the IP packet using buffer[]
    //    - construct the IP header ...
    //    - construct the TCP/UDP/ICMP header ...
    //    - fill in the data part if needed ...

    // Assining parts of the buffer to IP and ICMP headers
    struct sniff_ip *ip = (struct sniff_ip*) buffer;
    struct icmphdr *icmp = (struct icmphdr*) (buffer + sizeof(struct sniff_ip)); // In this code we use a ICMP structure from netinet

    // Converting IP addresses from dotted format to in_addr format
    inet_aton("1.1.1.1", &(ip->ip_src)); // Spoofed
    inet_aton("10.9.0.5", &(ip->ip_dst));

    // Assigning values to some important IP header fields, although it may not be needed to do so
    ip->ip_len = 2049;
    ip->ip_vhl = 4 << 4 | sizeof(struct sniff_ip) >> 2;
    ip->ip_p = IPPROTO_ICMP;  // Sending the packet with IP Protocol
    ip->ip_sum = cal_chksum((u_short*)ip, IP_HL(ip));

    // Spoofing ICMP fields and calculating its checksum
    icmp->type = 8;
    icmp->code = 0;
    icmp->un.echo.id = htons(1);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = ICMPChecksum((uint16_t*)icmp, sizeof(struct icmphdr));
    // Note: you should pay attention to the network/host byte order.
    /* Send out the IP packet.
    * ip_len is the actual size of the packet. */
    size_t ip_len = sizeof(struct sniff_ip) + sizeof(struct icmphdr);
    
    printf("%ld\n", ip_len);
    if(sendto(sd, buffer, ip_len, 0, (struct sockaddr *)&sin,
            sizeof(sin)) < 0) {
    perror("sendto() error"); exit(-1);
    }
    printf("One packet sent!\n");

    return 0;

}