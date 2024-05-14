#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

#include <pcap.h>

// analyze packets
void analyze_packet(const u_char *packet, struct pcap_pkthdr pkthdr);

// detailed analysis of different protocols
void analyze_ethernet(const u_char *packet);
void analyze_ip(const u_char *packet);
void analyze_tcp(const u_char *packet);
void analyze_udp(const u_char *packet);

#endif