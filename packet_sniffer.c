#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>

void ProcessPacket_addr(unsigned char* buffer) {

  struct ip *ip_header_data = (struct ip *)(buffer + 14);
  
  printf("Destination IP: %s\n", inet_ntoa(ip_header_data->ip_dst));
  printf("Source IP: %s\n", inet_ntoa(ip_header_data->ip_src));
}

void ProcessPacket_port(unsigned char* buffer) {

    struct ip *ip_header = (struct ip *)(buffer + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(buffer + 14 + ip_header->ip_hl * 4); // Skip IP header

    // Extract source and destination ports
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    printf("Destination Port: %d\n", dst_port);
    printf("Source Port: %d\n", src_port);

}


int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	//Create a raw socket that shall sniff

    printf("Starting\n");
	int sock_raw = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));


	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}

    printf("Socket initiated\n");	

	while(1)

	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size < 0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}

        printf("-------\n");
        ProcessPacket_port(buffer);
        ProcessPacket_addr(buffer);
        
	}

	printf("Finished");
	return 0;
}