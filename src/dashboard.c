#include "dashboard.h"
#include <ncurses.h>

void init_dashboard() {
  initscr();
  cbreak();
  noecho();
  curs_set(FALSE);
  refresh();
}

void update_dashboard(int packet_count, int tcp_count, int udp_count, int other_count, int bytes) {
  clear();
  mvprintw(0, 0, "Packet Capture Statistics");
  mvprintw(1, 0, "-------------------------");
  mvprintw(2, 0, "Total Packets: %d", packet_count);
  mvprintw(3, 0, "TCP Packets: %d", tcp_count);
  mvprintw(4, 0, "UDP Packets: %d", udp_count);
  mvprintw(5, 0, "Other Packets: %d", other_count);
  mvprintw(6, 0, "Total Bytes: %d", bytes);
  refresh();
}

void end_dashboard() {
  endwin();
}
