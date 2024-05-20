#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

pcap_t* initialize_packet_capture();

void start_packet_capture(pcap_t *pcap_handle, const char *filter_expr);

void stop_packet_capture(pcap_t *pcap_handle);

void update_packet_size_distribution(int packet_size);

void update_top_talkers(const char *src_ip);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
