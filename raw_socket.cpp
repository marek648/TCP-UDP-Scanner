#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "raw_socket.h"
#include <netinet/udp.h>



/*
	Generic checksum calculation function
	Inspired by : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-sockets-c-code-linux/
	Edited by: Marek Lorinc (xlorin00@stud.fit.vutbr.cz)
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

// Helper function for ipv6 checksum
// Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
// URL: http://www.pdbuchan.com/rawsock/rawsock.html
uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}
// Function for tcp ipv6 checksum
// Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
// URL: http://www.pdbuchan.com/rawsock/rawsock.html
uint16_t tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr));
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}
// Function for udp ipv6 checksum
// Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
// URL: http://www.pdbuchan.com/rawsock/rawsock.html
uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphd, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphd.len, sizeof (udphd.len));
  ptr += sizeof (udphd.len);
  chksumlen += sizeof (udphd.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphd.source, sizeof (udphd.source));
  ptr += sizeof (udphd.source);
  chksumlen += sizeof (udphd.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphd.dest, sizeof (udphd.dest));
  ptr += sizeof (udphd.dest);
  chksumlen += sizeof (udphd.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphd.len, sizeof (udphd.len));
  ptr += sizeof (udphd.len);
  chksumlen += sizeof (udphd.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}


int open_socket(bool tcp,bool ipv4){
	int s;
	if(tcp == true){
		if (ipv4 == true)
		{
			s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
		}
		else{
			s = socket (PF_INET6, SOCK_RAW, IPPROTO_TCP);
		}
		
	}
	else{
		if (ipv4 == true)
		{
			s = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
		}
		else{
			s = socket (PF_INET6, SOCK_RAW, IPPROTO_UDP);
		}
		
	}
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if(ipv4 == true){
		if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
		{
			perror("Error setting IP_HDRINCL");
			exit(1);
		}
	}
	else{
		if (setsockopt (s, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof (one)) < 0)
		{
			perror("Error setting IP_HDRINCL");
			exit(1);
		}
	}
	

	return s;
}

/*	Function to set ipv4 and ipv6 header TCP
	IPV4 Inspired by : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-sockets-c-code-linux/
	Edited by: Marek Lorinc (xlorin00@stud.fit.vutbr.cz)
	IPV6 Inspired by : P.D. Buchan (pdbuchan@yahoo.com)
	URL: http://www.pdbuchan.com/rawsock/rawsock.html
	*/
void set_ip_header(struct iphdr *iph,struct ip6_hdr *ip6,char *source_ip,char *target_ip,char *data,bool ipv4){

	if (ipv4 == true)
	{
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
		iph->id = htonl (54321);	//Id of this packet
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;		//Set to 0 before calculating checksum
		iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
		iph->daddr = inet_addr (target_ip);
	}
	else{
		ip6->ip6_ctlun.ip6_un2_vfc = 0x60;
	    ip6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);;
	    ip6->ip6_hops = 255;
	    ip6->ip6_nxt = IPPROTO_TCP;
	    ip6->ip6_plen = htons(sizeof(struct tcphdr));
		if(inet_pton(AF_INET6,source_ip,&(ip6->ip6_src))!=1)
			fprintf(stderr, "Problem\n" );	//Spoof the source ip address
		if(inet_pton(AF_INET6,target_ip,&(ip6->ip6_dst ))!=1)
			fprintf(stderr, "Problem\n" );
	}
	

}
/*	Function to set ipv4 and ipv6 header UDP
	IPV4 Inspired by : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-udp-sockets-c-linux/
	Edited by: Marek Lorinc (xlorin00@stud.fit.vutbr.cz)
	IPV6 Inspired by : P.D. Buchan (pdbuchan@yahoo.com)
	URL: http://www.pdbuchan.com/rawsock/rawsock.html
	*/
void set_udp_ip_header(struct iphdr *iph,struct ip6_hdr *ip6,char *source_ip,char *target_ip,char *data,bool ipv4){

	//Fill in the IP Header
	if (ipv4 == true)
	{
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
		iph->id = htonl (54321);	//Id of this packet
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = 17; // UDP
		iph->check = 0;		//Set to 0 before calculating checksum
		iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
		iph->daddr = inet_addr (target_ip);
	}
	else{
		//ip6->ip6_ctlun.ip6_un2_vfc = 0x60;
	    ip6->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);;
	    ip6->ip6_hops = 255;
	    ip6->ip6_nxt = IPPROTO_UDP;
	    ip6->ip6_plen = htons(sizeof(struct udphdr));
		if(inet_pton(AF_INET6,source_ip,&(ip6->ip6_src))!=1)
			fprintf(stderr, "Problem\n" );	//Spoof the source ip address
		if(inet_pton(AF_INET6,target_ip,&(ip6->ip6_dst ))!=1)
			fprintf(stderr, "Problem\n" );
	}

}

/*	Function to set TCP
	Author : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-sockets-c-code-linux/
	*/
void set_tcp_header(struct tcphdr *tcph,int port){
	
	//TCP Header
	tcph->source = htons (1234);
	tcph->dest = htons (port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (65535);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;
}
/*	Function to set UDP
	Author : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-udp-sockets-c-linux/
	*/
void set_udp_header(struct udphdr *udph,int port){
	
	//UDP Header
	udph->source = htons (1234);
	udph->dest = htons (port);
	udph->len = htons(sizeof(struct udphdr));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
}
/*	Function to calculate tcp checksum by pseudoheader
	Author : Silver Moon (m00n.silv3r@gmail.com)
	URL: https://www.binarytides.com/raw-sockets-c-code-linux/
	*/
void tcp_checksum(struct ip6_hdr *ip6,struct pseudo_header psh,struct tcphdr *tcph,char *source_ip,char *target_ip,int size_tcphdr,int data_size,bool ipv4){
	//Now the TCP checksum
	char  *pseudogram;
	if (ipv4 == true)
	{
		psh.source_address = inet_addr( source_ip );
		psh.dest_address = inet_addr (target_ip);
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(size_tcphdr + data_size);
		
		int psize = sizeof(struct pseudo_header) + size_tcphdr + data_size;
		pseudogram = (char *) malloc(psize);
		
		memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , size_tcphdr + data_size);
		
		tcph->check = csum( (unsigned short*) pseudogram , psize);
	}
	else{

		tcph->check = tcp6_checksum(*ip6,*tcph);
	}
}
//Function to calculate udp checksum ipv6(ipv4 is not necessary)
void ipv6_udp_checksum(struct ip6_hdr *ip6,struct udphdr *udph){
	uint8_t *data;
	data = (uint8_t *) malloc (sizeof (uint8_t));
	memset (data, 0, sizeof (uint8_t));
	udph->check = udp6_checksum(*ip6,*udph,data,0);

}
//Send raw packet to target destination
void send_raw_packet(int s,char *datagram,int iph_len,struct sockaddr_in sin,struct sockaddr_in6 sin6,bool ipv4){
	if (ipv4 == true)
	{
		if (sendto (s, datagram, iph_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		{
			perror("sendto failed");
			exit(1);
		}
	}
	else{
		iph_len = ntohs(iph_len);
		if (sendto (s, datagram, sizeof(struct ip6_hdr) + iph_len,	0, (struct sockaddr *) &sin6, sizeof (sin6)) < 0)
		{
			perror("sendto failed");
			exit(1);
		}
	}
}
	
	
