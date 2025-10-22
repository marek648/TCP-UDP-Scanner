#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <netinet/in.h>
#include <arpa/inet.h>

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr,int nbytes);
int open_socket(bool tcp,bool ipv4);
void set_ip_header(struct iphdr *iph,struct ip6_hdr *ip6,char *source_ip,char *target_ip,char *data,bool ipv4);
void set_tcp_header(struct tcphdr *tcph,int port);
void tcp_checksum(struct ip6_hdr *ip6,struct pseudo_header psh,struct tcphdr *tcph,char *source_ip,char *target_ip,int size_tcphdr,int data_size,bool ipv4);
void send_raw_packet(int s,char *datagram,int iph_len,struct sockaddr_in sin,struct sockaddr_in6 sin6,bool ipv4);
void set_udp_ip_header(struct iphdr *iph,struct ip6_hdr *ip6,char *source_ip,char *target_ip,char *dat,bool ipv4);
void set_udp_header(struct udphdr *udph,int port);
void ipv6_udp_checksum(struct ip6_hdr *ip6,struct udphdr *udph);
