#include "packet_capture.h"
#include "packet_analysis.h"
#include "dashboard.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

static int packet_count = 0;
static int tcp_count = 0;
static int udp_count = 0;
static int other_count = 0;
static int total_bytes = 0;

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
    exit(EXIT_FAILURE);
  }

  printf("Device Found: %s\n", dev->name);

  pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
    exit(EXIT_FAILURE);
  }

  pcap_freealldevs(alldevs);
  return handle;
}

void start_packet_capture(pcap_t *pcap_handle, const char *filter_expr) {
  struct bpf_program fp;

  if (pcap_compile(pcap_handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expr, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(pcap_handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expr, pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE);
  }

  printf("Starting packet capture with filter: %s\n", filter_expr);
  init_dashboard();
  pcap_loop(pcap_handle, 0, packet_handler, NULL);
}

void stop_packet_capture(pcap_t *pcap_handle) {
  pcap_close(pcap_handle);
  end_dashboard();
  printf("Packet Capture stopped \n");
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  packet_count++;
  total_bytes += pkthdr->len;

  struct ether_header *eth_header = (struct ether_header *)packet;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_p == IPPROTO_TCP) {
      tcp_count++;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
      udp_count++;
    } else {
      other_count++;
    }
  } else {
    other_count++;
  }
  
  analyze_packet(packet, *pkthdr);
  update_dashboard(packet_count, tcp_count, udp_count, other_count, total_bytes);
}
