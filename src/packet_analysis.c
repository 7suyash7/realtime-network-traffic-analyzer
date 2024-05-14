#include "packet_analysis.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// conditional macros for platform-specific field names in tcp, udp.
#if defined(__APPLE__)
#define TCP_SOURCE_PORT th_sport
#define TCP_DEST_PORT th_dport
#define TCP_SEQ_NUM th_seq
#define TCP_ACK_NUM th_ack
#define UDP_SOURCE_PORT uh_sport
#define UDP_DEST_PORT uh_dport
#define UDP_LEN uh_ulen
#else
#define TCP_SOURCE_PORT source
#define TCP_DEST_PORT dest
#define TCP_SEQ_NUM seq
#define TCP_ACK_NUM ack_seq
#define UDP_SOURCE_PORT source
#define UDP_DEST_PORT dest
#define UDP_LEN len
#endif

void analyze_packet(const u_char *packet, struct pcap_pkthdr pkthdr) {
  // for now just printing a packet was analyzed
  printf("Analyzing Packet Length: %d\n", pkthdr.len);
  analyze_ethernet(packet);
}

void analyze_ethernet(const u_char *packet) {
  struct ether_header *eth_header = (struct ether_header *)packet;
  printf("Ethernet Header\n");
  printf("\t|-Source Address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
          eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], 
          eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
  printf("\t|-Destination Address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
          eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], 
          eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
  printf("\t|-Protocol : %u\n", (unsigned short)eth_header->ether_type);

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    analyze_ip(packet + sizeof(struct ether_header));
  }
}

void analyze_ip(const u_char *packet) {
  struct ip *ip_header = (struct ip *)(packet);
  printf("IP Header\n");
  printf("\t|-Source IP : %s\n", inet_ntoa(ip_header->ip_src));
  printf("\t|-Destination IP : %s\n", inet_ntoa(ip_header->ip_dst));
  printf("\t|-Protocol : %d\n", (unsigned int)ip_header->ip_p);

  if (ip_header->ip_p == IPPROTO_TCP) {
    analyze_tcp(packet + sizeof(struct ip));
  } else if (ip_header->ip_p == IPPROTO_UDP) {
    analyze_udp(packet + sizeof(struct ip));
  }
}

void analyze_tcp(const u_char *packet) {
  struct tcphdr *tcp_header = (struct tcphdr *)(packet);
  printf("TCP Header\n");
  printf("\t|-Source Port: %u\n", ntohs(tcp_header->TCP_SOURCE_PORT));
  printf("\t|-Destination Port: %u\n", ntohs(tcp_header->TCP_DEST_PORT));
  printf("\t|-Sequence Number: %u\n", ntohl(tcp_header->TCP_SEQ_NUM));
  printf("\t|-Acknowledgement Number: %u\n", ntohl(tcp_header->TCP_ACK_NUM));
}

void analyze_udp(const u_char *packet) {
  struct udphdr *udp_header = (struct udphdr*)(packet);
  printf("UDP Header\n");
  printf("\t|-Source Port : %u\n", ntohs(udp_header->UDP_SOURCE_PORT));
  printf("\t|-Destination Port : %u\n", ntohs(udp_header->UDP_DEST_PORT));
  printf("\t|-Length : %u\n", ntohs(udp_header->UDP_LEN));
}
