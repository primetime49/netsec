#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

void filter_icmp(char * buf) {
    struct ipheader * iph = (struct ipheader * ) (buf + sizeof(struct ether_header));

    if (iph->iph_protocol != 1) {
        return;
    }
    char * data = (char *) (iph) + sizeof(struct ipheader) + sizeof(struct icmpheader)
                    + sizeof(struct ipheader) + sizeof(struct udpheader);
    printf("source ip: %s\n", inet_ntoa(iph->iph_sourceip));
    printf("data: %s\n", data);
    printf("----------\n");
}

void main(int argc, char **argv) {
    
    struct packet_mreq mr;
    char buf[1500];
    int sock;
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
                sizeof(mr));
    
    while (1){
        bzero(buf, 1500);
        int data_size = recvfrom(sock, buf, 1500, 0, NULL, NULL);

        if (data_size>0){
            filter_icmp(buf);
        }
    }
    close(sock);
}