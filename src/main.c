#include "packet_capture.h"

int main() {
  pcap_t *handle = initialize_packet_capture();
  start_packet_capture(handle, "ip");
  stop_packet_capture(handle);
  return 0;
}