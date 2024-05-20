#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <netinet/in.h>

#define MAX_TOP_TALKERS 10

void init_dashboard();

void update_dashboard(int total_packets, int tcp_packets, int udp_packets, int icmp_packets, int icmpv6_packets, int ipv4_packets, int ipv6_packets, int other_packets, int total_bytes, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol);

void display_packet_size_distribution(int packet_size_distribution[]);

void display_top_talkers(char top_talkers[MAX_TOP_TALKERS][INET6_ADDRSTRLEN], int talker_counts[]);

void update_protocol_distribution(int tcp_count, int udp_count, int icmp_count, int icmpv6_count);

void end_dashboard();

#endif
