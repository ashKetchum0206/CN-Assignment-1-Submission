#include <stdio.h>					 //For standard things
#include <stdlib.h>					 //malloc
#include <string.h>					 //memset
#include <netinet/tcp.h>		 //Provides declarations for tcp header
#include <netinet/ip.h>			 //Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include<sys/types.h>
#include<unistd.h>
#include<ctime>
#include<map>
#include<vector>
#include<string>
#include<netinet/if_ether.h>
#include<iostream>

#define PORT_SIZE 8
#define COMMAND_SIZE 150
#define PID_SIZE 10


std::map< uint16_t , std::map <std::string , bool> > port_map;

void getProcess_ids(uint16_t src_port) {

  char port[PORT_SIZE]; // To hold the converted string (including the null terminator)
		
  sprintf(port, "%u", src_port);
  
  char command[COMMAND_SIZE] = "lsof -i | grep ";
  strcat(command , port);
  strcat(command, " | awk '{print$2}' ");

  FILE *openFile = popen(command, "r");
  char pid[PID_SIZE]; 

  while (fgets(pid, sizeof(pid), openFile)){
  
      int len = strlen(pid);
      if(pid[len - 1] == '\n') pid[len - 1] = '\0';
        
      std::string pid_str = pid;
      if(port_map.find(src_port) == port_map.end()) port_map[src_port] = {};
      port_map[src_port][pid_str] = true;

      std::cout << pid_str << std::endl;
  }

  pclose(openFile);  

}

void ProcessPacket_addr(unsigned char *buffer){


	struct ip *ip_header_data = (struct ip *)(buffer + 14);


	printf("Destination IP: %s\n", inet_ntoa(ip_header_data->ip_dst));
	printf("Source IP: %s\n", inet_ntoa(ip_header_data->ip_src));
}

void ProcessPacket_port(unsigned char *buffer){


	struct ip *ip_header = (struct ip *)(buffer + 14);
	struct tcphdr *tcp_header = (struct tcphdr *)(buffer + 14 + ip_header->ip_hl * 4); // Skip IP header

	// Extract source and destination ports
	uint16_t src_port = ntohs(tcp_header->th_sport);
	uint16_t dst_port = ntohs(tcp_header->th_dport);

	printf("Destination Port: %d\n", dst_port);
	printf("Source Port: %d\n", src_port);

	getProcess_ids(src_port);

}

int main()
{
	int data_size;
    socklen_t saddr_size;
	struct sockaddr saddr;
	struct in_addr in;

	unsigned char *buffer = (unsigned char *)malloc(65536); 

	// Create a raw socket that shall sniff

	printf("Starting\n");
	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}

	printf("Socket initiated\n");
    time_t initial_time = time(NULL);

	while (1){
	
		saddr_size = sizeof saddr;

		// Receive a packet
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		if (data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}

		printf("-------\n");
		ProcessPacket_port(buffer);
		ProcessPacket_addr(buffer);

        time_t present_time = time(NULL);
        if(present_time - initial_time >= 30) {
            break;
        }

	}

    std::cout << "Ports captured:"<< std::endl;
    for(auto i = port_map.begin() ;i != port_map.end(); i++) {
        std:: cout << i->first<< std:: endl;
    }

    std:: cout << "Entering inquiry loop. Input 'quit' to exit" << std::endl;

    while(1) {

        std:: string inp;
        std:: cout << "Enter port to get all the PIDs that used it:";
        std:: cin >> inp;

        if(inp == "quit") break;
        int inp_int = stoi(inp);
        uint16_t inp_final = (uint16_t) inp_int;
        
        for(auto i = port_map[inp_final].begin(); i!= port_map[inp_final].end(); i++) {
            std::cout << i->first << std:: endl;
        }

        std::cout << '\n';
    }

	return 0;
}