// Final Code - Working
#include <stdio.h>           //For standard things
#include <stdlib.h>          //malloc
#include <string.h>          //memset
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>     //Provides declarations for udp header
#include <netinet/tcp.h>     //Provides declarations for tcp header
#include <netinet/ip.h>      //Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include<map>
#include<string>
#include<vector>

#define BUFFER_SIZE 65536

FILE *logfile;
ssize_t bufferSize;

std::map < std::vector<std:: string> , bool > flow_map;

void ProcessPacket(unsigned char *buffer)
{
  struct ip *ip_header_data = (struct ip *)(buffer + 14);

  printf("Destination IP: %s\n", inet_ntoa(ip_header_data->ip_dst));
  printf("Source IP: %s\n", inet_ntoa(ip_header_data->ip_src));

  struct tcphdr *tcp_header = (struct tcphdr *)(buffer + 14 + ip_header_data->ip_hl * 4); // Skip IP header

  int header_size = 14 + ip_header_data->ip_hl * 4 + tcp_header->th_off*4;

  // Extract source and destination ports
  uint16_t src_port = ntohs(tcp_header->th_sport);
  uint16_t dst_port = ntohs(tcp_header->th_dport);

  printf("Destination Port: %d\n", dst_port);
  printf("Source Port: %d\n", src_port);

  std::string dest_port = std::to_string(dst_port);
  std::string source_port = std:: to_string(src_port);

  std:: string dest_ip = inet_ntoa(ip_header_data->ip_dst);
  std:: string source_ip = inet_ntoa(ip_header_data->ip_src);

  std:: vector<std::string> flow_tuple = {source_ip , dest_ip, source_port , dest_port}; 

  if(flow_map.find(flow_tuple) == flow_map.end()) {

    flow_map[flow_tuple] = true;
    fprintf(logfile, "\n");
    fprintf(logfile, "%s    ", inet_ntoa(ip_header_data->ip_src));
    fprintf(logfile, "%s    ", inet_ntoa(ip_header_data->ip_dst));
    fprintf(logfile, "%d    ", src_port);
    fprintf(logfile, "%d    ", dst_port);
    fprintf(logfile, "\n");
  }

}

int main()
{
  int data_size;
  socklen_t saddr_size;
  struct sockaddr saddr;
  struct in_addr in;

  unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); // Its Big!

  // Create a raw socket that shall sniff

  logfile = fopen("flows.txt", "w");

  if (logfile == NULL)
  {
    printf("Unable to create file.");
  }

  else {
    fprintf(logfile, "The Data Format followed is:\n");
    fprintf(logfile, "Source IP    |    Destination IP    |    Source Port    |    Destination Port\n");
  }

  printf("Starting\n");
  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (sock_raw < 0)
  {
    printf("Socket Error\n");
    return 1;
  }

  printf("Socket initiated\n");

  while (1)
  {
    saddr_size = sizeof saddr;
    // Receive a packet
    bufferSize = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
    if (bufferSize < 0)
    {
      printf("Recvfrom error , failed to get packets\n");
      return 1;
    }

    printf("-------\n");
    ProcessPacket(buffer);
    printf("The total number of flows observed till now are %d\n" , flow_map.size());
  }

  return 0;
}
