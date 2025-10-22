#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "raw_socket.h"
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include<netinet/ip6.h>

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void my_packet_handler_udp(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info_udp(const u_char *packet, struct pcap_pkthdr packet_header);
void ProcessArguments(int argc, char** argv,char *tcp_ports,char *udp_ports,char *target_ip,char *interface);
void Control_arg(char *tcp_ports,char *udp_ports,char *target_ip);
void Get_hostname(char *target_ip,char *converted_source_ip,bool *ipv4);
void tcp_loop_abort();
void tcp_terminate_process(int signum);
void udp_loop_abort();
void udp_terminate_process(int signum);
void get_all_ports(char *tcp_p,int tcp_ports[],bool *tcp_range,char *udp_p,int udp_ports[],bool *udp_range);
void print_start(char *dest_ip,char *target_ip,bool *printed);
void get_my_ip(char *interface,char *source_ip,char *device,bool ipv4);
void store_ports(char *p,int ports[],bool *range);
void set_device(char *dest_ip,char *source_ip,char *dev,char *device,char *dev_localhost);
void initialize_filter(char *dev,bpf_u_int32 *ip,bpf_u_int32 *subnet_mask);
void set_filter(char *filter_exp,bpf_u_int32 ip);
void send_packet_get_answer(int s,char *datagram,int iph_len,sockaddr_in sin,sockaddr_in6 sin6,bool tcp,bool ipv4);
void get_info_tcp_port(struct ip6_hdr *ip6,struct iphdr *iph,struct tcphdr *tcph,char *datagram,char *dest_ip,char *target_ip,char *source_ip,struct pseudo_header psh,char *data,char *filter_exp,bpf_u_int32 ip,int s,sockaddr_in sin,struct sockaddr_in6 sin6,int port,bool ipv4,int len_ipv6);
void get_info_udp_port(struct ip6_hdr *ip6,struct iphdr *iph,struct udphdr *udph,char *datagram,char *dest_ip,char *target_ip,char *source_ip,struct pseudo_header psh,char *data,char *filter_exp,bpf_u_int32 ip,int s,sockaddr_in sin,struct sockaddr_in6 sin6,int port,bool ipv4,int len_ipv6);
void check_scale(int tcp_int_ports[]);
void data_ip_config(sockaddr_in *sin,sockaddr_in6 *sin6,char **data,char **data_udp,char *datagram,char *dest_ip,bool ipv4);
//Global variables to use breakloop in signals
pcap_t *handle;
bool not_delivered = false;

int main(int argc, char *argv[]) {
	/* VARIABLES DECLARATION*/
	//Arguments
	char interface[1024] = "None";
	char tcp_ports[1024] = "None";
	char udp_ports[1024] = "None";
	char target_ip[1024] = "None";
	//Ports	
	static int tcp_int_ports[1024];
	static int udp_int_ports[1024];
	bool tcp_range;
	bool udp_range;
	//For pcap filter
	char dev[1024];
    char device[1024];
    char dev_localhost[] = "lo";
    char filter_exp[1024];
    bpf_u_int32 subnet_mask, ip;
    //For raw socket
    char datagram[4096]; 
    char source_ip[50];
    char dest_ip[50];
    char *data;
    char *data_udp;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
	struct pseudo_header psh;
	//Check if start is already printed
	bool printed = false;
	bool ipv4 = true;	


    //CODE
    //Store and Control values in arguments
	ProcessArguments(argc,argv,tcp_ports,udp_ports,target_ip,interface);
	Control_arg(tcp_ports,udp_ports,target_ip);
	//Store all ports(tcp and udp) to array
	get_all_ports(tcp_ports,tcp_int_ports,&tcp_range,udp_ports,udp_int_ports,&udp_range);
	
    
	//START SETTINGS
    //Datagram to represent the packet
	//zero out the packet buffer
	memset (datagram, 0, 4096);	
    //Convert Hostname to IP
    Get_hostname(target_ip,dest_ip,&ipv4);
    //Data part of raw socket TCP
    data_ip_config(&sin,&sin6,&data,&data_udp,datagram,dest_ip,ipv4);
    
    //get my ip and interface and store to variable
    get_my_ip(interface,source_ip,device,ipv4);
    set_device(dest_ip,source_ip,dev,device,dev_localhost);
    //Initialize filter
    initialize_filter(dev, &ip, &subnet_mask);
    //Ip header decl
    struct iphdr *iph = (struct iphdr *) datagram;
    struct ip6_hdr *ip6 = (struct ip6_hdr *) datagram;
    


    //TCP FILTER
    if (tcp_range == false && strcmp(tcp_ports,"None")!=0 )
    {
	    int s = open_socket(true,ipv4);
	    //Set Ip header and initialize TCP header
		set_ip_header(iph,ip6,source_ip,dest_ip,data,ipv4);
		struct tcphdr *tcph;
		//Ip checksum
		if (ipv4 == true){
			tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
			iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		}
		else{
			tcph = (struct tcphdr *) (datagram + sizeof (struct ip6_hdr));
		}

    	print_start(dest_ip,target_ip,&printed);
    	for (int i = 0; tcp_int_ports[i] != 0; ++i)
	    	get_info_tcp_port(ip6,iph,tcph,datagram,dest_ip,target_ip,source_ip,psh,data,filter_exp,ip,s,sin,sin6,tcp_int_ports[i],ipv4,ip6->ip6_plen);
	    close(s);
    }
    else if(tcp_range == true && strcmp(tcp_ports,"None")!=0 ){//Port set as range
    	int s = open_socket(true,ipv4);
    	//Set Ip header and intialize TCP header
		set_ip_header(iph,ip6,source_ip,dest_ip,data,ipv4);
		struct tcphdr *tcph;
		//Ip checksum
		if (ipv4 == true){
			iph->check = csum ((unsigned short *) datagram, iph->tot_len);
			tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
		}
		else{
			tcph = (struct tcphdr *) (datagram + sizeof (struct ip6_hdr));
		}
		//Check if scale is valid
    	check_scale(tcp_int_ports);
    	print_start(dest_ip,target_ip,&printed);
    	for (int i = tcp_int_ports[0] ; i <= tcp_int_ports[1] ; ++i)
    		get_info_tcp_port(ip6,iph,tcph,datagram,dest_ip,target_ip,source_ip,psh,data,filter_exp,ip,s,sin,sin6,i,ipv4,ip6->ip6_plen);
    	close(s);
    }


    //UDP FILTER
    if(udp_range == false && strcmp(udp_ports,"None")!=0 ){
    	int s = open_socket(false,ipv4);
		set_udp_ip_header(iph,ip6,source_ip,dest_ip,data_udp,ipv4);
		struct udphdr *udph;
		if (ipv4 == true)
		{
			udph = (struct udphdr *) (datagram + sizeof (struct ip));
			//Ip checksum
			iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		}
		else{
			udph = (struct udphdr *) (datagram + sizeof (struct ip6_hdr));
		}

		
		print_start(dest_ip,target_ip,&printed);
		for (int i = 0; udp_int_ports[i] != 0; ++i)
	    	get_info_udp_port(ip6,iph,udph,datagram,dest_ip,target_ip,source_ip,psh,data,filter_exp,ip,s,sin,sin6,udp_int_ports[i],ipv4,ip6->ip6_plen);
    }
    else if(udp_range == true && strcmp(udp_ports,"None")!=0 ){
    	int s = open_socket(false,ipv4);
    	//Set Ip header and intialize TCP header
    	set_udp_ip_header(iph,ip6,source_ip,dest_ip,data_udp,ipv4);
		struct udphdr *udph;
		if (ipv4 == true)
		{
			udph = (struct udphdr *) (datagram + sizeof (struct ip));
			//Ip checksum
			iph->check = csum ((unsigned short *) datagram, iph->tot_len);
		}
		else{
			udph = (struct udphdr *) (datagram + sizeof (struct ip6_hdr));
		}

		//Check if scale is valid
    	check_scale(udp_int_ports);
    	print_start(dest_ip,target_ip,&printed);
    	for (int i = udp_int_ports[0] ; i <= udp_int_ports[1] ; ++i)
    		get_info_udp_port(ip6,iph,udph,datagram,dest_ip,target_ip,source_ip,psh,data,filter_exp,ip,s,sin,sin6,i,ipv4,ip6->ip6_plen);
    }

    pcap_close(handle);
    return 0;
}
//Configuration of data (in our case it is set to empty)
void data_ip_config(sockaddr_in *sin,sockaddr_in6 *sin6,char **data,char **data_udp,char *datagram,char *dest_ip,bool ipv4){
	if (ipv4 == true)
    {
    	*data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
		strcpy(*data , "");
		//Data part of raw socket UDP
		*data_udp = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
		strcpy(*data_udp, "");
		//some address resolution
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(dest_ip);
    }
    else{
    	*data = datagram + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
		strcpy(*data , "");
		//Data part of raw socket UDP
		*data_udp = datagram + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
		strcpy(*data_udp, "");
		//some address resolution
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = 0;
		inet_pton(AF_INET6,dest_ip,&(sin6->sin6_addr.s6_addr));
    }
	
}
//Check if scale in argument is valid
void check_scale(int tcp_int_ports[]){
	//printf("%d\n",tcp_int_ports[1] );
	//printf("%d\n",tcp_int_ports[0] );
	if (tcp_int_ports[0] > tcp_int_ports[1]){
		fprintf(stderr,"Error scale %s\n", pcap_geterr(handle));
		exit(1);
	}
}
//Get all info from tcp ports and print it to stdout 
void get_info_tcp_port(struct ip6_hdr *ip6,struct iphdr *iph,struct tcphdr *tcph,char *datagram,char *dest_ip,char *target_ip,char *source_ip,struct pseudo_header psh,char *data,char *filter_exp,bpf_u_int32 ip,int s,sockaddr_in sin,sockaddr_in6 sin6,int port,bool ipv4,int len_ipv6){
	sin.sin_port = htons(port);
    set_tcp_header(tcph,port);
    tcp_checksum(ip6,psh,tcph,source_ip,dest_ip,sizeof(struct tcphdr),strlen(data),ipv4);
    sprintf(filter_exp,"tcp and src port %d and src %s and dst %s",port,dest_ip,source_ip);
    set_filter(filter_exp,ip);
    
    printf("%d/tcp",port );
    if(ipv4 == true){
    	send_packet_get_answer(s,datagram,iph->tot_len,sin,sin6,true,ipv4);
    }
    else{
    	send_packet_get_answer(s,datagram,len_ipv6,sin,sin6,true,ipv4);
    }
}
//Get all info from udp ports and prit it to stdout
void get_info_udp_port(struct ip6_hdr *ip6,struct iphdr *iph,struct udphdr *udph,char *datagram,char *dest_ip,char *target_ip,char *source_ip,struct pseudo_header psh,char *data,char *filter_exp,bpf_u_int32 ip,int s,sockaddr_in sin,sockaddr_in6 sin6,int port,bool ipv4,int len_ipv6){
	sin.sin_port = htons(port);
	set_udp_header(udph,port);
	if (ipv4 == false)
	{
		ipv6_udp_checksum(ip6,udph);
		sprintf(filter_exp,"icmp6 and src %s and dst %s",dest_ip,source_ip);
	}
	else{
		sprintf(filter_exp,"icmp and src %s and dst %s",dest_ip,source_ip);
	}
	
	set_filter(filter_exp,ip);
    printf("%d/udp",port );
    if(ipv4 == true){
    	send_packet_get_answer(s,datagram,iph->tot_len,sin,sin6,false,ipv4);
    }
    else{
    	send_packet_get_answer(s,datagram,len_ipv6,sin,sin6,false,ipv4);
    }
}
//Send raw packet and wait for answer
//If answer not coming for 1 second wait loop is interupted by signal and try to send packet once more
void send_packet_get_answer(int s,char *datagram,int iph_len,sockaddr_in sin,sockaddr_in6 sin6,bool tcp,bool ipv4){
	//printf("Dlzka: %d\n",iph_len );
	if (tcp == true)
	{
		send_raw_packet(s,datagram,iph_len,sin,sin6,ipv4);
		tcp_loop_abort();
		pcap_loop(handle, 1, my_packet_handler, NULL);
	}
	else{
		send_raw_packet(s,datagram,iph_len,sin,sin6,ipv4);
		udp_loop_abort();
		pcap_loop(handle, 1, my_packet_handler_udp, NULL);
	}
    if (not_delivered == true){
	    if (tcp == true){
	    	send_raw_packet(s,datagram,iph_len,sin,sin6,ipv4);
			tcp_loop_abort();
			pcap_loop(handle, 1, my_packet_handler, NULL);
		}
		else{
			send_raw_packet(s,datagram,iph_len,sin,sin6,ipv4);
			udp_loop_abort();
			pcap_loop(handle, 1, my_packet_handler_udp, NULL);
		}
	}
    not_delivered = false;

}

//Set filter for incoming packets packet type,src ip,dst ip and source port
//Inspired by:Dev Dungeon
//URL: https://www.devdungeon.com/content/using-libpcap-c
void set_filter(char *filter_exp,bpf_u_int32 ip){
	struct bpf_program filter;
	if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        fprintf(stderr,"Bad filter - %s\n", pcap_geterr(handle));
        exit(2);
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr,"Error setting filter - %s\n", pcap_geterr(handle));
        exit(2);
    }
}
//Initialize filter on packets
//Inspired by:Dev Dungeon
//URL: https://www.devdungeon.com/content/using-libpcap-c
void initialize_filter(char *dev,bpf_u_int32 *ip,bpf_u_int32 *subnet_mask){
	char error_buffer[PCAP_ERRBUF_SIZE];
	if (pcap_lookupnet(dev, ip, subnet_mask, error_buffer) == -1) {
        fprintf(stderr,"Could not get information for device: %s\n", dev);
        exit(2);
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 100, error_buffer);
    if (handle == NULL) {
        fprintf(stderr,"Could not open %s - %s\n", dev, error_buffer);
        exit(2);
    }
}
//Check if packet has loopback addres if yes device must be set to "lo"
void set_device(char *dest_ip,char *source_ip,char *dev,char *device,char *dev_localhost){
	if (strcmp(dest_ip,"127.0.0.1") == 0 or strcmp(dest_ip,source_ip) == 0)
    {
    	strcpy(dev,dev_localhost);
    }
    else{
    	strcpy(dev,device);
    }
}
// Get myIp according to ip version of hostname
//IPv4 inspired by URL:https://stackoverflow.com/questions/20800319/how-do-i-get-my-ip-address-in-c-on-linux 

void get_my_ip(char *interface,char *source_ip,char *device,bool ipv4){
	ifaddrs *ifap,*tmp;
	getifaddrs(&ifap);
	tmp = ifap;
	char addr[50];
	if (strcmp(interface,"None") == 0)
	{
		while(tmp){
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET && ipv4 == true)
		    {
		    	if (strcmp(tmp->ifa_name,"lo") != 0)
		    	{
		    		struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
		    		strcpy(device,tmp->ifa_name);
		    		strcpy(source_ip,inet_ntoa(pAddr->sin_addr));	
		    		return;
		    	}
		    	
		    }
		    else if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET6 && ipv4 == false)
		    {
		    	if (strcmp(tmp->ifa_name,"lo") != 0)
		    	{
		    		struct sockaddr_in6 *pAddr = (struct sockaddr_in6 *)tmp->ifa_addr;
		    		strcpy(device,tmp->ifa_name);

		    		inet_ntop(AF_INET6,&pAddr->sin6_addr,addr,sizeof(addr));
		    		//printf("addr = %s\n", addr);
		    		strcpy(source_ip,addr);	
		    		return;
		    	}
		    	
		    }
		    tmp = tmp->ifa_next;
		}
	}
	else{
		while(tmp){
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET && ipv4 == true)
		    {
				if (strcmp(tmp->ifa_name,interface) == 0)
			    {
			   		struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
			   		strcpy(device,tmp->ifa_name);
			   		strcpy(source_ip,inet_ntoa(pAddr->sin_addr));	
			   		return;
			   	}
		   	}
		   	else if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET6 && ipv4 == false)
		    {
				if (strcmp(tmp->ifa_name,interface) == 0)
			    {
			   		struct sockaddr_in6 *pAddr = (struct sockaddr_in6 *)tmp->ifa_addr;
		    		strcpy(device,tmp->ifa_name);

		    		inet_ntop(AF_INET6,&pAddr->sin6_addr,addr,sizeof(addr));
		    		//printf("addr = %s\n", addr);
		    		strcpy(source_ip,addr);	
		    		return;
			   	}
		   	}
	    tmp = tmp->ifa_next;
		}
	}
	fprintf(stderr, "Cant find appropriate interface or not supported IPv6\n");
	exit(1);
	
	
}

void print_start(char *dest_ip,char *target_ip,bool *printed){
	if (*printed == true)
	{
		return;
	}
	if (strcmp(dest_ip,target_ip) == 0)
	{
		printf("Interesting ports on %s:\n",dest_ip);
    	printf("PORT \t STATE\n");
	}
	else{
		printf("Interesting ports on %s (%s):\n",target_ip,dest_ip);
    	printf("PORT \t STATE\n");
	}
	*printed = true;
}

//Check type of ports and then store them
void get_all_ports(char *tcp_p,int tcp_ports[],bool *tcp_range,char *udp_p,int udp_ports[],bool *udp_range){
	*tcp_range = false;
	*udp_range = false;
	if (strcmp(tcp_p,"None") != 0){
		store_ports(tcp_p,tcp_ports,tcp_range);
	}
	if (strcmp(udp_p,"None") != 0){
		store_ports(udp_p,udp_ports,udp_range);
	}

}
//Store all ports to array
//If scale is required then first and last id store to array and flag range is set to true
void store_ports(char *p,int ports[],bool *range){
	int len = strlen(p);
	char one_port[20];
	memset(one_port,'\0',20);
	int k = 0;

	for (int i = 0,j=0; i < len; ++i)
		{
			
			if(isdigit(p[i]) and p[i]!='\0'){
				one_port[j++] = p[i];
			}
			else{
				if (p[i] == '-')
				{
					if (*range == false)
					{
						*range = true;
					}
					else{
						fprintf(stderr, "Used 2 tcp/udp ranges\n");
						exit(1);
					}
				}
				else if(p[i] == ','){
					if(*range == true){
						fprintf(stderr, "Combination range and values not allowed\n");
						exit(1);
					}
					
				}
				else{
					fprintf(stderr, "Wrong character in tcp/udp ports\n");
					exit(1);
				}

				j=0;
				ports[k] = atoi(one_port);
				memset(one_port,'\0',20);
				if (ports[k] <= 0 or ports[k] > 65535)
				{
					fprintf(stderr, "Wrong port\n");
					exit(1);
				}
				k++;
			}
		}
		ports[k] = atoi(one_port);
		memset(one_port,'\0',20);
		if (ports[k] <= 0 or ports[k] > 65535)
		{
			fprintf(stderr, "Wrong port\n");
			exit(1);
		}
}

//Function which is called in pcap loop when required packet TCP is catched
//Inspired by:Dev_dungeon
//URL: https://www.devdungeon.com/content/using-libpcap-c
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    return;
}
//Function which is called in pcap loop when required packet UDP is catched
//Inspired by:Dev_dungeon
//URL: https://www.devdungeon.com/content/using-libpcap-c
void my_packet_handler_udp(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info_udp(packet_body, *packet_header);
    return;
}

//Signal function isnpired by: Samuel Klatchko
//URL: https://stackoverflow.com/questions/2377309/how-to-use-pcap-breakloop
void tcp_loop_abort()
{
    signal(SIGALRM, tcp_terminate_process); 
    alarm(1);
}
//Signal to abort pcap_loop 
//In tcp -> port is filtered
void tcp_terminate_process(int signum)
{
	if (not_delivered == true)
  	{
  		printf("\t filtered\n");
  	}
  	else{
  		not_delivered = true;
  	}
  	pcap_breakloop(handle);
}

void udp_loop_abort()
{
    signal(SIGALRM, udp_terminate_process); 
    alarm(1);
}
//Signal to abort pcap_loop 
//In udp -> port is open
void udp_terminate_process(int signum)
{
	if (not_delivered == true)
  	{
  		printf("\t open\n");
  	}
  	else{
  		not_delivered = true;
  	}
  
 	pcap_breakloop(handle);
} 


//Check flags of TCP header if it SYN and ACK print to stdout that port is open
//IF flags are ACK and RES print to stdout that port is closed
//Else port is unknown
void print_packet_info(const u_char *frame, struct pcap_pkthdr packet_header) {
	if (frame[12]== 0x8 && frame[13] == 0x00)
	{
		int ihl = frame[14]&0x0f;
		u_char eph[100];
		memcpy(eph,frame+4*ihl+14,100);
		int tcp_flags = eph[13];
		int  synack = tcp_flags & 0x3f;
		if(synack == 0x12){
			printf("\t open\n");
		}
		else if(synack == 0x14){
			printf("\t closed\n");
		}
		else
			printf("\t unknown\n");
	}
	else{
		int synack = frame[67];
		if(synack == 0x12){
			printf("\t open\n");
		}
		else if(synack == 0x14){
			printf("\t closed\n");
		}
		else
			printf("\t unknown\n");
	}
}
//Check flags of ICMP packet in ipv4 if it is type 3 and code 3 then packet is closed
//Else unknown icmp packet
//In ipv6 must be type 1 and code 4 
void print_packet_info_udp(const u_char *frame, struct pcap_pkthdr packet_header) {
	if (frame[12]== 0x8 && frame[13] == 0x00)
	{
		int ihl = frame[14]&0x0f;
		u_char eph[100];
		memcpy(eph,frame+4*ihl+14,100);
		if(eph[0] == 0x3 && eph[1] == 0x3){
			printf("\t closed\n");
		}
		else
			printf("\t unknown type icmp\n");
	}
	else{
		if(frame[54] == 0x1 && frame[55] == 0x4){
			printf("\t closed\n");
		}
		else
			printf("\t unknown type icmpv6\n");
		/*for (int i = 0; i < 100; ++i)
		{
			printf("[%d]%X\n",i,frame[i] );
		}*/
	}
	

}
//Function to process arguments and store ports,hostname and interface to variables
void ProcessArguments(int argc, char** argv,char *tcp_ports,char *udp_ports,char *target_ip,char *interface){
	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i],"-i") == 0)
		{
			i++;
			if (i < argc)
			{
				if(argv[i][0] == '-'){
					fprintf(stderr, "Option -i needs parameter\n");
	            	exit(1);
				}
				strcpy(interface ,argv[i]);
			}
			else{
				fprintf(stderr, "Option -i needs parameter\n");
	            exit(1);
			}
		}
		else if (strcmp(argv[i],"-pu") == 0)
		{
			i++;
			if (i < argc)
			{
				if(argv[i][0] == '-'){
					fprintf(stderr, "Option -pu needs parameter\n");
	            	exit(1);
				}
				strcpy(udp_ports,argv[i]);
			}
			else{
				fprintf(stderr, "Option -pu needs parameter\n");
	            exit(1);
			}
		}
		else if (strcmp(argv[i],"-pt") == 0)
		{
			i++;
			if (i < argc)
			{
				if(argv[i][0] == '-'){
					fprintf(stderr, "Option -pt needs parameter\n");
	            	exit(1);
				}
				strcpy(tcp_ports,argv[i]);
			}
			else{
				fprintf(stderr, "Option -pt needs parameter\n");
	            exit(1);
			}
		}
		else{
			strcpy(target_ip,argv[i]);
		}
	}

}
//Check if necessary argument are set
void Control_arg(char *tcp_ports,char *udp_ports,char *target_ip){
	if (strcmp(target_ip ,"None") == 0)
    {
    	fprintf(stderr, "Not entered IP\n");
	    exit(1);
    }
    if (strcmp(udp_ports ,"None") == 0 && strcmp(tcp_ports,"None") == 0)
    {
    	fprintf(stderr, "Not entered ports to be scanned\n");
	    exit(1);
    }
}
//Change hostname to ip a strore type of ip to variable
//Inspired by : URL:https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
void Get_hostname(char *target_ip,char *converted_source_ip,bool *ipv4){
	struct addrinfo hints;
    struct addrinfo *result;
    int s;
    char ipstr[1024];
    struct in_addr  *addr; 
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */
    s = getaddrinfo(target_ip, "80", &hints, &result);
    //printf("%d\n",result->ai_addr->sin_family );
    if (s != 0) {
    	hints.ai_family = AF_INET6;
    	s = getaddrinfo(target_ip, "80", &hints, &result);
    	if (s!=0)
    	{
    		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        	exit(EXIT_FAILURE);
    	}
    	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)result->ai_addr; 
        addr = (struct in_addr *) &(ipv6->sin6_addr); 
        *ipv4 = false;
    }
    else{
    	struct sockaddr_in *ipv = (struct sockaddr_in *)result->ai_addr; 
        addr = &(ipv->sin_addr);  
    }
    inet_ntop(result->ai_family, addr, ipstr, sizeof ipstr); 
    strcpy(converted_source_ip, ipstr);

/*

	hostent * record = gethostbyname(target_ip);
	if(record == NULL)
	{
		fprintf(stderr,"%s is unavailable\n", target_ip);
		exit(1);
	}

	in_addr * address = (in_addr * )record->h_addr;
	strcpy(converted_source_ip, inet_ntoa(* address));*/
}