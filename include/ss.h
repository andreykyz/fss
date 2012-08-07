/*
 * ss.h
 *
 *  Created on: 27.07.2012
 *      Author: Andrey Kuznetsov
 */

#ifndef SS_H_
#define SS_H_

#include <netinet/tcp.h>

struct channel_info {
    uint8_t snd_wscale;
    uint8_t rcv_wscale;
    double rto;
    double rtt; // in ms
    double rtt_var; // in ms
    double ato;
    uint32_t cwnd; // in mss
    uint32_t ssthresh;
    uint32_t send; // in kbyte/sec)
    double rcv_rtt;
    uint32_t rcv_space;
};
struct channel_info channel_info_st;

struct channel_info* format_info(struct tcp_info * info);
struct tcp_info* get_tcp_info(int lport, int rport);
struct channel_info* get_format_tcp_info(int lport, int rport);
void show_tcp_info_struct(struct tcp_info* info);

#endif /* SS_H_ */
