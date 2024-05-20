#include "packet_analysis.h"
#include "logger.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// conditional macros for platform-specific field names in tcp, udp, and icmp.
#if defined(__APPLE__)
#define TCP_SOURCE_PORT th_sport
#define TCP_DEST_PORT th_dport
#define TCP_SEQ_NUM th_seq
#define TCP_ACK_NUM th_ack
#define TCP_DO_OFF th_off
#define TCP_URG_FLAG th_flags & TH_URG
#define TCP_ACK_FLAG th_flags & TH_ACK
#define TCP_PSH_FLAG th_flags & TH_PUSH
#define TCP_RST_FLAG th_flags & TH_RST
#define TCP_SYN_FLAG th_flags & TH_SYN
#define TCP_FIN_FLAG th_flags & TH_FIN
#define TCP_WINDOW th_win
#define TCP_CHECK th_sum
#define TCP_URG_PTR th_urp
#define UDP_SOURCE_PORT uh_sport
#define UDP_DEST_PORT uh_dport
#define UDP_LEN uh_ulen
#define UDP_CHECKSUM uh_sum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_ID icmp_id
#define ICMP_SEQ icmp_seq
#else
#define TCP_SOURCE_PORT source
#define TCP_DEST_PORT dest
#define TCP_SEQ_NUM seq
#define TCP_ACK_NUM ack_seq
#define TCP_DO_OFF doff
#define TCP_URG_FLAG urg
#define TCP_ACK_FLAG ack
#define TCP_PSH_FLAG psh
#define TCP_RST_FLAG rst
#define TCP_SYN_FLAG syn
#define TCP_FIN_FLAG fin
#define TCP_WINDOW window
#define TCP_CHECK check
#define TCP_URG_PTR urg_ptr
#define UDP_SOURCE_PORT source
#define UDP_DEST_PORT dest
#define UDP_LEN len
#define UDP_CHECKSUM check
#define ICMP_TYPE type
#define ICMP_CODE code
#define ICMP_CHECKSUM checksum
#define ICMP_ID un.echo.id
#define ICMP_SEQ un.echo.sequence
#endif

void analyze_packet(const u_char *packet, struct pcap_pkthdr pkthdr) {
  char log_msg[1024];
  // printf("Analyzing Packet Length: %d\n", pkthdr.len);
  log_message(log_msg);
  analyze_ethernet(packet);
}

void analyze_ethernet(const u_char *packet) {
  struct ether_header *eth_header = (struct ether_header *)packet;
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
      "Ethernet Header\n"
      "\t|-Source Address : %02x:%02x:%02x:%02x:%02x:%02x\n"
      "\t|-Destination Address : %02x:%02x:%02x:%02x:%02x:%02x\n"
      "\t|-Protocol : %u\n",
      eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
      eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
      eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
      eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5],
      (unsigned short)eth_header->ether_type);

  log_message(log_msg);

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    analyze_ip(packet + sizeof(struct ether_header));
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    analyze_ipv6(packet + sizeof(struct ether_header));
  }
}

void analyze_ip(const u_char *packet) {
  struct ip *ip_header = (struct ip *)(packet);
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
      "IP Header\n"
      "\t|-Source IP : %s\n"
      "\t|-Destination IP : %s\n"
      "\t|-Protocol : %d\n",
      inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), (unsigned int)ip_header->ip_p);

  log_message(log_msg);

  switch (ip_header->ip_p) {
    case IPPROTO_TCP:
      analyze_tcp(packet + sizeof(struct ip));
      break;
    case IPPROTO_UDP:
      analyze_udp(packet + sizeof(struct ip));
      break;
    case IPPROTO_ICMP:
      analyze_icmp(packet + sizeof(struct ip));
      break;
    default:
      snprintf(log_msg, sizeof(log_msg), "Unknown IP Protocol: %d\n", ip_header->ip_p);
      log_message(log_msg);
      break;
  }
}

void analyze_ipv6(const u_char *packet) {
  struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet);
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, &ip6_header->ip6_src, src, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst, INET6_ADDRSTRLEN);
  
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "IPv6 Header\n"
    "\t|-Source IP : %s\n"
    "\t|-Destination IP : %s\n"
    "\t|-Next Header : %d\n",
    src, dst, (unsigned int)ip6_header->ip6_nxt);

  log_message(log_msg);

  switch (ip6_header->ip6_nxt) {
    case IPPROTO_TCP:
      analyze_tcp(packet + sizeof(struct ip6_hdr));
      break;
    case IPPROTO_UDP:
      analyze_udp(packet + sizeof(struct ip6_hdr));
      break;
    case IPPROTO_ICMPV6:
      analyze_icmpv6(packet + sizeof(struct ip6_hdr));
      break;
    default:
      snprintf(log_msg, sizeof(log_msg), "Unknown IPv6 Next Header: %d\n", ip6_header->ip6_nxt);
      log_message(log_msg);
      break;
  }
}

void analyze_tcp(const u_char *packet) {
  struct tcphdr *tcp_header = (struct tcphdr *)(packet);
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "TCP Header\n"
    "\t|-Source Port: %u\n"
    "\t|-Destination Port: %u\n"
    "\t|-Sequence Number: %u\n"
    "\t|-Acknowledgement Number: %u\n"
    "\t|-Header Length: %u bytes\n"
    "\t|-Flags: %s%s%s%s%s%s\n"
    "\t|-Window Size: %u\n"
    "\t|-Checksum: %u\n"
    "\t|-Urgent Pointer: %u\n",
    ntohs(tcp_header->TCP_SOURCE_PORT), ntohs(tcp_header->TCP_DEST_PORT), ntohl(tcp_header->TCP_SEQ_NUM),
    ntohl(tcp_header->TCP_ACK_NUM), tcp_header->TCP_DO_OFF * 4,
    tcp_header->TCP_URG_FLAG ? "URG " : "", tcp_header->TCP_ACK_FLAG ? "ACK " : "", tcp_header->TCP_PSH_FLAG ? "PSH " : "",
    tcp_header->TCP_RST_FLAG ? "RST " : "", tcp_header->TCP_SYN_FLAG ? "SYN " : "", tcp_header->TCP_FIN_FLAG ? "FIN " : "",
    ntohs(tcp_header->TCP_WINDOW), ntohs(tcp_header->TCP_CHECK), tcp_header->TCP_URG_PTR);

  log_message(log_msg);

  if (ntohs(tcp_header->TCP_SOURCE_PORT) == 80 || ntohs(tcp_header->TCP_DEST_PORT) == 80) {
    analyze_http(packet + (tcp_header->TCP_DO_OFF * 4));
  }
}

void analyze_udp(const u_char *packet) {
  struct udphdr *udp_header = (struct udphdr*)(packet);
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "UDP Header\n"
    "\t|-Source Port : %u\n"
    "\t|-Destination Port : %u\n"
    "\t|-Length : %u\n"
    "\t|-Checksum : %u\n",
    ntohs(udp_header->UDP_SOURCE_PORT), ntohs(udp_header->UDP_DEST_PORT), ntohs(udp_header->UDP_LEN),
    ntohs(udp_header->UDP_CHECKSUM));

  log_message(log_msg);

  if (ntohs(udp_header->UDP_SOURCE_PORT) == 53 || ntohs(udp_header->UDP_DEST_PORT) == 53) {
    analyze_dns(packet + sizeof(struct udphdr));
  }
}

void analyze_icmp(const u_char *packet) {
#if defined(__APPLE__)
  struct icmp *icmp_header = (struct icmp *)(packet);
#else
  struct icmphdr *icmp_header = (struct icmphdr *)(packet);
#endif

  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "ICMP Header\n"
    "\t|-Type : %u\n"
    "\t|-Code : %u\n"
    "\t|-Checksum : %u\n",
    icmp_header->ICMP_TYPE, icmp_header->ICMP_CODE, ntohs(icmp_header->ICMP_CHECKSUM));

  log_message(log_msg);

#if defined(__APPLE__)
  if (icmp_header->ICMP_TYPE == ICMP_ECHO) {
    snprintf(log_msg, sizeof(log_msg),
      "\t|-Identifier : %u\n"
      "\t|-Sequence Number : %u\n",
      ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));

    log_message(log_msg);
    }
#else
  if (icmp_header->ICMP_TYPE == ICMP_ECHO) {
    snprintf(log_msg, sizeof(log_msg),
      "\t|-Identifier : %u\n"
      "\t|-Sequence Number : %u\n",
      ntohs(icmp_header->ICMP_ID), ntohs(icmp_header->ICMP_SEQ));

    log_message(log_msg);
  }
#endif
}

void analyze_icmpv6(const u_char *packet) {
  struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(packet);

  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "ICMPv6 Header\n"
    "\t|-Type : %u\n"
    "\t|-Code : %u\n"
    "\t|-Checksum : %u\n",
    icmp6_header->icmp6_type, icmp6_header->icmp6_code, ntohs(icmp6_header->icmp6_cksum));

  log_message(log_msg);

  if (icmp6_header->icmp6_type == ICMP6_ECHO_REQUEST || icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {
    snprintf(log_msg, sizeof(log_msg),
      "\t|-Identifier : %u\n"
      "\t|-Sequence Number : %u\n",
      ntohs(icmp6_header->icmp6_data16[0]), ntohs(icmp6_header->icmp6_data16[1]));

    log_message(log_msg);
  }
}

void analyze_http(const u_char *packet) {
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg), "HTTP Data\n%s\n", packet);
  log_message(log_msg);
}

void analyze_dns(const u_char *packet) {
  char log_msg[1024];
  snprintf(log_msg, sizeof(log_msg),
    "DNS Data\n"
    "\t|-Transaction ID: 0x%04x\n"
    "\t|-Flags: 0x%04x\n"
    "\t|-Questions: %u\n"
    "\t|-Answer RRs: %u\n"
    "\t|-Authority RRs: %u\n"
    "\t|-Additional RRs: %u\n",
    (packet[0] << 8) + packet[1], (packet[2] << 8) + packet[3],
    (packet[4] << 8) + packet[5], (packet[6] << 8) + packet[7],
    (packet[8] << 8) + packet[9], (packet[10] << 8) + packet[11]);

  log_message(log_msg);

  snprintf(log_msg, sizeof(log_msg), "\t|-Queries:\n");
  log_message(log_msg);

  const u_char *query = packet + 12;
  int i = 0;
  while (query[i] != 0) {
      snprintf(log_msg, sizeof(log_msg), "%c", query[i]);
      log_message(log_msg);
      i++;
  }
}
