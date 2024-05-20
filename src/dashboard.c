#include "dashboard.h"
#include <ncurses.h>
#include <string.h>

#define PACKET_SIZE_BUCKETS 10
#define MAX_TOP_TALKERS 10

static int packet_size_distribution[PACKET_SIZE_BUCKETS];
static char top_talkers[MAX_TOP_TALKERS][INET6_ADDRSTRLEN];
static int talker_counts[MAX_TOP_TALKERS];

void init_dashboard() {
  initscr();
  start_color();
  use_default_colors();
  init_pair(1, COLOR_CYAN, -1);
  init_pair(2, COLOR_GREEN, -1);
  init_pair(3, COLOR_YELLOW, -1);
  init_pair(4, COLOR_RED, -1);
  init_pair(5, COLOR_MAGENTA, -1);
  cbreak();
  noecho();
  curs_set(FALSE);
  refresh();
}

void update_dashboard(int total_packets, int tcp_packets, int udp_packets, int icmp_packets, int icmpv6_packets, int ipv4_packets, int ipv6_packets, int other_packets, int total_bytes, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol) {
  clear();
  mvprintw(0, 0, "Packet Capture Statistics");
  mvprintw(1, 0, "-------------------------");
  mvprintw(2, 0, "Total Packets: %d", total_packets);
  mvprintw(3, 0, "Total Bytes: %d", total_bytes);
  mvprintw(4, 0, "Average Packet Size: %.2f bytes", (float)total_bytes / total_packets);

  mvprintw(6, 0, "Packet Types:");
  mvprintw(7, 0, "TCP Packets: %d (%.2f%%)", tcp_packets, (tcp_packets / (float)total_packets) * 100);
  mvprintw(8, 0, "UDP Packets: %d (%.2f%%)", udp_packets, (udp_packets / (float)total_packets) * 100);
  mvprintw(9, 0, "ICMP Packets: %d (%.2f%%)", icmp_packets, (icmp_packets / (float)total_packets) * 100);
  mvprintw(10, 0, "ICMPv6 Packets: %d (%.2f%%)", icmpv6_packets, (icmpv6_packets / (float)total_packets) * 100);

  mvprintw(12, 0, "IP Version:");
  mvprintw(13, 0, "IPv4 Packets: %d (%.2f%%)", ipv4_packets, (ipv4_packets / (float)total_packets) * 100);
  mvprintw(14, 0, "IPv6 Packets: %d (%.2f%%)", ipv6_packets, (ipv6_packets / (float)total_packets) * 100);

  mvprintw(16, 0, "Other Packets:");
  mvprintw(17, 0, "Other Packets: %d (%.2f%%)", other_packets, (other_packets / (float)total_packets) * 100);

  mvprintw(19, 0, "Last Packet Details:");
  mvprintw(20, 0, "Protocol: %s", protocol);
  mvprintw(21, 0, "Source IP: %s", src_ip);
  mvprintw(22, 0, "Source Port: %d", src_port);
  mvprintw(23, 0, "Destination IP: %s", dst_ip);
  mvprintw(24, 0, "Destination Port: %d", dst_port);

  refresh();
}

void display_packet_size_distribution(int packet_size_distribution[]) {
  mvprintw(26, 0, "Packet Size Distribution:");
  for (int i = 0; i < PACKET_SIZE_BUCKETS; i++) {
    mvprintw(27 + i, 0, "%d-%d bytes: %d", i * 100, (i + 1) * 100 - 1, packet_size_distribution[i]);
  }
}

void display_top_talkers(char top_talkers[MAX_TOP_TALKERS][INET6_ADDRSTRLEN], int talker_counts[]) {
  mvprintw(37, 0, "Top Talkers:");
  for (int i = 0; i < MAX_TOP_TALKERS; i++) {
    if (talker_counts[i] > 0) {
      mvprintw(38 + i, 0, "%s: %d packets", top_talkers[i], talker_counts[i]);
    }
  }
}

void update_protocol_distribution(int tcp_count, int udp_count, int icmp_count, int icmpv6_count) {
    // Implement protocol distribution update logic if needed
}

void end_dashboard() {
    endwin();
}
