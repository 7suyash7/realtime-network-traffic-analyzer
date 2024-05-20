#include "packet_capture.h"
#include "packet_analysis.h"
#include "dashboard.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>

#define UPDATE_INTERVAL 1
#define MAX_TOP_TALKERS 10
#define PACKET_SIZE_BUCKETS 10

struct packet_stats {
  int total_packets;
  int tcp_packets;
  int udp_packets;
  int icmp_packets;
  int icmpv6_packets;
  int ipv4_packets;
  int ipv6_packets;
  int other_packets;
  int total_bytes;
  int packet_size_distribution[PACKET_SIZE_BUCKETS];
  char top_talkers[MAX_TOP_TALKERS][INET6_ADDRSTRLEN];
  int talker_counts[MAX_TOP_TALKERS];
};

struct packet_stats stats = {0};

pcap_t* initialize_packet_capture() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_if_t *dev;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  dev = alldevs;
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    pcap_freealldevs(alldevs);
    exit(EXIT_FAILURE);
  }

  printf("Device Found: %s\n", dev->name);

  pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
    pcap_freealldevs(alldevs);
    exit(EXIT_FAILURE);
  }

  pcap_freealldevs(alldevs);
  return handle;
}

void start_packet_capture(pcap_t *pcap_handle, const char *filter_expr) {
  struct bpf_program fp;

  if (pcap_compile(pcap_handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expr, pcap_geterr(pcap_handle));
    pcap_close(pcap_handle);
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(pcap_handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expr, pcap_geterr(pcap_handle));
    pcap_freecode(&fp);
    pcap_close(pcap_handle);
    exit(EXIT_FAILURE);
  }

  pcap_freecode(&fp);
  printf("Starting packet capture with filter: %s\n", filter_expr);
  init_logger("packets.log");
  init_dashboard();
  pcap_loop(pcap_handle, 0, packet_handler, NULL);
}

void stop_packet_capture(pcap_t *pcap_handle) {
  pcap_close(pcap_handle);
  end_dashboard();
  close_logger();
  printf("Packet Capture stopped \n");
}

void update_packet_size_distribution(int packet_size) {
  int index = packet_size / 100;
  if (index >= PACKET_SIZE_BUCKETS) {
    index = PACKET_SIZE_BUCKETS - 1;
  }
  stats.packet_size_distribution[index]++;
}

void update_top_talkers(const char *src_ip) {
  for (int i = 0; i < MAX_TOP_TALKERS; i++) {
    if (strcmp(stats.top_talkers[i], src_ip) == 0) {
      stats.talker_counts[i]++;
      return;
    }
  }

  for (int i = 0; i < MAX_TOP_TALKERS; i++) {
    if (stats.talker_counts[i] == 0) {
      strncpy(stats.top_talkers[i], src_ip, INET6_ADDRSTRLEN);
      stats.talker_counts[i] = 1;
      return;
    }
  }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  (void)user_data;

  static time_t last_update_time = 0;
  time_t current_time = time(NULL);

  stats.total_packets++;
  stats.total_bytes += pkthdr->len;

  struct ether_header *eth_header = (struct ether_header *)(packet);
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];
  int src_port = 0;
  int dst_port = 0;
  char protocol[10];

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    stats.ipv4_packets++;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    switch (ip_header->ip_p) {
      case IPPROTO_TCP: {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        stats.tcp_packets++;
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        snprintf(protocol, sizeof(protocol), "TCP");
        break;
      }
      case IPPROTO_UDP: {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        stats.udp_packets++;
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        snprintf(protocol, sizeof(protocol), "UDP");
        break;
      }
      case IPPROTO_ICMP: {
        stats.icmp_packets++;
        snprintf(protocol, sizeof(protocol), "ICMP");
        break;
      }
      default: {
        stats.other_packets++;
        snprintf(protocol, sizeof(protocol), "Other");
        break;
      }
    }
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    stats.ipv6_packets++;
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

    switch(ip6_header->ip6_nxt) {
      case IPPROTO_TCP: {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        stats.tcp_packets++;
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        snprintf(protocol, sizeof(protocol), "TCP");
        break;
      }
      case IPPROTO_UDP: {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        stats.udp_packets++;
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        break;
      }
      case IPPROTO_ICMPV6: {
        stats.icmpv6_packets++;
        snprintf(protocol, sizeof(protocol), "ICMPV6");
        break;
      }
      default: {
        stats.other_packets++;
        snprintf(protocol, sizeof(protocol), "Other");
        break;
      }
    }
  } else {
    stats.other_packets++;
    snprintf(protocol, sizeof(protocol), "Other");
  }

  analyze_packet(packet, *pkthdr);
  log_packet(pkthdr, packet, src_ip, dst_ip, src_port, dst_port, protocol);

  update_packet_size_distribution(pkthdr->len);
  update_top_talkers(src_ip);

  if (difftime(current_time, last_update_time) >= UPDATE_INTERVAL) {
    update_dashboard(stats.total_packets, stats.tcp_packets, stats.udp_packets, stats.icmp_packets, stats.icmpv6_packets, stats.ipv4_packets, stats.ipv6_packets, stats.other_packets, stats.total_bytes, src_ip, dst_ip, src_port, dst_port, protocol);
    display_packet_size_distribution(stats.packet_size_distribution);
    display_top_talkers(stats.top_talkers, stats.talker_counts);
    last_update_time = current_time;
  }
}

