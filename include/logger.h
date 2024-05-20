#ifndef LOGGER_H
#define LOGGER_H

#include <pcap.h>

void init_logger(const char *filename);

void log_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol);

void log_message(const char *message);

void close_logger();

#endif
