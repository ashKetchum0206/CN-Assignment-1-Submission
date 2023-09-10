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

#define BUFFER_SIZE 65536

FILE *logfile;
ssize_t bufferSize;

void PrintData(const u_char *data, int Size)
{
  int i, j;
  for (i = 0; i < Size; i++)
  {
    if (data[i] >= 32 && data[i] <= 128)
      fprintf(logfile, "%c", (unsigned char)data[i]); // if its a number or alphabet

    else
      fprintf(logfile, "."); // otherwise print a dot
  }
}

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

  // if(inet_ntoa(ip_header_data->ip_src) == "127.0.0.1") {
  //   printf("Localhost\n");
  //   PrintData(buffer + header_size, bufferSize - header_size);
  // }
  // uint16_t check = ntohs(tcp_header->check);

  // if(check == (uint16_t)((unsigned int)62518)) {
  //   PrintData(buffer + header_size, bufferSize - header_size);
  // }


  fprintf(logfile, "\n");
  fprintf(logfile, "%s    ", inet_ntoa(ip_header_data->ip_src));
  fprintf(logfile, "%d    ", ntohs(tcp_header->th_sport));
  fprintf(logfile, "%s    ", inet_ntoa(ip_header_data->ip_dst));
  fprintf(logfile, "%d    ", ntohs(tcp_header->th_dport));
  fprintf(logfile, "%d    ", ntohs(tcp_header->check));
  PrintData(buffer + header_size, bufferSize - header_size);
  fprintf(logfile, "\n");
}

int main()
{
  int saddr_size, data_size;
  struct sockaddr saddr;
  struct in_addr in;

  unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); // Its Big!

  // Create a raw socket that shall sniff

  logfile = fopen("output.txt", "w");
  if (logfile == NULL)
  {
    printf("Unable to create file.");
  }

  else {
    fprintf(logfile, "The Data Format followed is:\n");
    fprintf(logfile, "Source IP    |    Source Port    |    Destination IP    |    Destination Port    |    TCP Checksum    |    Payload\n");
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
  }

  

  printf("Finished");
  return 0;
}
