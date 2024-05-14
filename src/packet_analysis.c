#include "packet_analysis.h"
#include <stdio.h>

void analyze_packet(const u_char *packet, struct pcap_pkthdr pkthdr) {
  // for now just printing a packet was analyzed
  printf("Analyzing Packet Length: %d\n", pkthdr.len);
}
