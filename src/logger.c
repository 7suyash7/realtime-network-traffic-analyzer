#include <logger.h>
#include <stdio.h>
#include <time.h>

static FILE *logfile = NULL;

void init_logger(const char *filename) {
  logfile = fopen(filename, "w");
  if (logfile == NULL) {
    perror("Error opening log file");
  }
}

void log_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, const char *src_ip, const char *dst_ip, int src_port, int dst_port, const char *protocol) {
  if (logfile == NULL) return;

  time_t now = time(NULL);
  struct tm *local = localtime(&now);

  fprintf(logfile, "Timestamp: %04d-%02d-%02d %02d:%02d:%02d\n",
          local->tm_year + 1900, local->tm_mon + 1, local->tm_mday,
          local->tm_hour, local->tm_min, local->tm_sec);

  fprintf(logfile, "Packet Length: %d\n", pkthdr->len);
  fprintf(logfile, "Protocol: %s\n", protocol);
  fprintf(logfile, "Source IP: %s\n", src_ip);
  fprintf(logfile, "Source Port: %d\n", src_port);
  fprintf(logfile, "Destination IP: %s\n", dst_ip);
  fprintf(logfile, "Destination Port: %d\n", dst_port);

  fprintf(logfile, "Payload: \n");
  for (unsigned i = 0; i < pkthdr->len; i++) {
    fprintf(logfile, "%02x ", packet[i]);
    if ((i + 1) % 16 == 0) fprintf(logfile, "\n");
  }

  fprintf(logfile, "\n\n");
  fflush(logfile);
}

void log_message(const char *message) {
  if (logfile == NULL) return;
  fprintf(logfile, "%s", message);
  fflush(logfile);
}

void close_logger() {
  if (logfile) {
    fclose(logfile);
    logfile = NULL;
  }
}
