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
    double rtt; // in ms (round trip time)
    double rtt_var; // in ms (jitter)
    double ato;
    uint32_t cwnd; // in mss
    uint32_t ssthresh;
    uint32_t send; // in kbyte/sec)
    double rcv_rtt;
    uint32_t rcv_space;
    uint32_t send_q;
    uint32_t recv_q;
    int lport;
    int rport;
};

void get_format_tcp_info(struct channel_info**, int channel_amount);

#endif /* SS_H_ */
