#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>

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

struct ipheader * fill_ip_header(char * buffer, u_int8_t * ttl, char * d_addr, char * s_addr, int packet_size) {
    struct ipheader * ip = (struct ipheader *) buffer;
    ip -> iph_ver = 4;
    ip -> iph_ihl = 5;
    ip -> iph_ttl = ttl;
    ip -> iph_destip.s_addr = inet_addr(d_addr);
    ip -> iph_sourceip.s_addr = inet_addr(s_addr);
    ip -> iph_protocol = IPPROTO_UDP;
    ip -> iph_len = htons(sizeof(struct ipheader) + packet_size);
    return ip;
}

struct udpheader * fill_udp_header(char * buffer, int msg_len) {
    struct udpheader * udp = (struct udpheader *) buffer;
    udp -> udp_sport = htons(12345);
    udp -> udp_dport = htons(9090);
    udp -> udp_ulen = htons(sizeof(struct udpheader) + msg_len);
    udp -> udp_sum = 0;
}

void main(int argc, char **argv) {
    char buffer[1500];
    u_int8_t * max_ttl = 20;
    char * src_ip = "192.168.0.1";
    char * dst_ip = "8.8.8.8";
    if (argc > 1) {
        src_ip = argv[1];
        dst_ip = argv[2];
        max_ttl = atoi(argv[3]);
    }
    struct sockaddr_in dest;
    char message[20];
    for (u_int8_t ttl = 1; ttl <= max_ttl; ++ttl){
        sprintf(message, "TTL %d\n", ttl);
        int msg_len = strlen(message);
        int iph_len = sizeof(struct ipheader);
        int udp_len = sizeof(struct udpheader);
        int total_length = iph_len + udp_len + msg_len;
        
        struct ipheader * ip = fill_ip_header(buffer, ttl, dst_ip, src_ip, udp_len + msg_len);
        struct udpheader * udp = fill_udp_header(buffer + iph_len, msg_len);

        strncpy(buffer+iph_len+udp_len, message, msg_len);

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        dest.sin_family = AF_INET;
        dest.sin_addr = ip->iph_destip;
        sendto(sock, ip, ntohs(ip->iph_len), 0,
                (struct sockaddr *) &dest, sizeof(dest));
        close(sock);
    }
}