#ifndef DASHBOARD_H
#define DASHBOARD_H

void init_dashboard();

void update_dashboard(int packet_count, int tcp_count, int udp_count, int other_count, int bytes);

void end_dashboard();

#endif
