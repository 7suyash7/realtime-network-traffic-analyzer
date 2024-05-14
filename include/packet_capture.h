#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

// intialize packet capture and return a handle to the pcap session
pcap_t* initialize_packet_capture();

// start packet capture with a specified filter expression
void start_packet_capture(pcap_t *pcap_handle, const char *filter_expr);

// stop packet capture process
void stop_packet_capture(pcap_t *pcap_handle);

// callbacks to handle captured packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
