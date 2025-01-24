#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

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

struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

int main(){

    int sd;
    struct sockaddr_in sin;
    char buffer[1024]; // You can change the buffer size
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
    struct sniff_ip *ip = (struct sniff_ip*) buffer;
    struct sniff_udp *udp = (struct sniff_udp*) (buffer + sizeof(struct sniff_ip));
    inet_aton("10.9.0.5", &(ip->ip_dst));
    inet_aton("1.1.1.1", &(ip->ip_src));
    ip->ip_len = 2049;
    ip->ip_vhl = 4 << 4 | sizeof(struct sniff_ip) >> 2;
    ip->ip_p = IPPROTO_UDP;
    udp->uh_dport = htons(10);
    udp->uh_sport = htons(10);
    udp->uh_ulen = 8;
    // char* payload = (char*) (buffer + sizeof(struct sniff_ip) + sizeof(struct sniff_udp));
    // payload[0] = 'r';
    // Note: you should pay attention to the network/host byte order.
    /* Send out the IP packet.
    * ip_len is the actual size of the packet. */
    size_t ip_len = sizeof(struct sniff_ip) + sizeof(struct sniff_udp);
    // printf("%ld\n", ip_len);
    if(sendto(sd, buffer, ip_len, 0, (struct sockaddr *)&sin,
            sizeof(sin)) < 0) {
    perror("sendto() error"); exit(-1);
    }
    printf("One packet sent!\n");

    return 0;

}