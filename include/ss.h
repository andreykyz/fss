/*
 * ss.h
 *
 *  Created on: 27.07.2012
 *      Author: andrey
 */

#ifndef SS_H_
#define SS_H_

struct tcp_info* get_tcp_info();
struct tcp_info* parce_tcp_info(struct filter *f, int socktype);

#endif /* SS_H_ */
