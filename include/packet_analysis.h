#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

#include <pcap.h>

// analyze packets
void analyze_packet(const u_char *packet, struct pcap_pkthdr pkthdr);

#endif