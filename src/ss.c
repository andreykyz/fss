/*
 * ss.c		"sockstat", socket statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>,
 * Andrey Kuznetsov <andreykyz@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <dirent.h>
#include <fnmatch.h>
#include <getopt.h>

#include "utils.h"
#include "rt_names.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "SNAPSHOT.h"

#include <sys/types.h>
#include <time.h>
#include "stats-hash.h"

#include <netinet/tcp.h>
#include <linux/inet_diag.h>
#include "ss.h"


int resolve_hosts = 0;
int resolve_services = 1;
int preferred_family = AF_UNSPEC;
int show_options = 0;
int show_details = 0;
int show_users = 0;
int show_mem = 0;
int show_tcpinfo = 0;
int continuous = 0;
struct timespec ts_mono, ts_rt;

int netid_width;
int state_width;
int addrp_width;
int addr_width;
int serv_width;
int screen_width;

static const char *TCP_PROTO = "tcp";
static const char *UDP_PROTO = "udp";
static const char *RAW_PROTO = "raw";
static const char *dg_proto = NULL;

struct channel_info** channel_info_ss;
struct port_pair** port_pair_ss;
int conn_counter;
int channel_amount_ss;
int error_tcp_info;

enum
{
	TCP_DB,
	DCCP_DB,
	UDP_DB,
	RAW_DB,
	UNIX_DG_DB,
	UNIX_ST_DB,
	PACKET_DG_DB,
	PACKET_R_DB,
	NETLINK_DB,
	MAX_DB
};

#define PACKET_DBM ((1<<PACKET_DG_DB)|(1<<PACKET_R_DB))
#define UNIX_DBM ((1<<UNIX_DG_DB)|(1<<UNIX_ST_DB))
#define ALL_DB ((1<<MAX_DB)-1)
#define printf(...) (void)0

enum {
	SS_UNKNOWN,
	SS_ESTABLISHED,
	SS_SYN_SENT,
	SS_SYN_RECV,
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,
	SS_CLOSE,
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,
	SS_CLOSING,
	SS_MAX
};

#define SS_ALL ((1<<SS_MAX)-1)

#include "ssfilter.h"

struct filter
{
	int dbs;
	int states;
	int families;
	struct ssfilter *f;
};

struct filter default_filter = {
	.dbs	=  (1<<TCP_DB),
	.states = SS_ALL & ~((1<<SS_LISTEN)|(1<<SS_CLOSE)|(1<<SS_TIME_WAIT)|(1<<SS_SYN_RECV)),
	.families= (1<<AF_INET)|(1<<AF_INET6),
};

struct filter current_filter;

static FILE *generic_proc_open(const char *env, const char *name)
{
	const char *p = getenv(env);
	char store[128];

	if (!p) {
		p = getenv("PROC_ROOT") ? : "/proc";
		snprintf(store, sizeof(store)-1, "%s/%s", p, name);
		p = store;
	}

	return fopen(p, "r");
}

static FILE *net_tcp_open(void)
{
	return generic_proc_open("PROC_NET_TCP", "net/tcp");
}

static FILE *net_tcp6_open(void)
{
	return generic_proc_open("PROC_NET_TCP6", "net/tcp6");
}

static FILE *net_udp_open(void)
{
	return generic_proc_open("PROC_NET_UDP", "net/udp");
}

static FILE *net_udp6_open(void)
{
	return generic_proc_open("PROC_NET_UDP6", "net/udp6");
}

static FILE *net_raw_open(void)
{
	return generic_proc_open("PROC_NET_RAW", "net/raw");
}

static FILE *net_raw6_open(void)
{
	return generic_proc_open("PROC_NET_RAW6", "net/raw6");
}

static FILE *net_unix_open(void)
{
	return generic_proc_open("PROC_NET_UNIX", "net/unix");
}

static FILE *net_packet_open(void)
{
	return generic_proc_open("PROC_NET_PACKET", "net/packet");
}

static FILE *net_netlink_open(void)
{
	return generic_proc_open("PROC_NET_NETLINK", "net/netlink");
}

static FILE *slabinfo_open(void)
{
	return generic_proc_open("PROC_SLABINFO", "slabinfo");
}

static FILE *net_sockstat_open(void)
{
	return generic_proc_open("PROC_NET_SOCKSTAT", "net/sockstat");
}

static FILE *net_sockstat6_open(void)
{
	return generic_proc_open("PROC_NET_SOCKSTAT6", "net/sockstat6");
}

static FILE *net_snmp_open(void)
{
	return generic_proc_open("PROC_NET_SNMP", "net/snmp");
}

static FILE *ephemeral_ports_open(void)
{
	return generic_proc_open("PROC_IP_LOCAL_PORT_RANGE", "sys/net/ipv4/ip_local_port_range");
}

struct user_ent {
	struct user_ent	*next;
	unsigned int	ino;
	int		pid;
	int		fd;
	char		process[0];
};

#define USER_ENT_HASH_SIZE	256
struct user_ent *user_ent_hash[USER_ENT_HASH_SIZE];

static int user_ent_hashfn(unsigned int ino)
{
	int val = (ino >> 24) ^ (ino >> 16) ^ (ino >> 8) ^ ino;

	return val & (USER_ENT_HASH_SIZE - 1);
}

static void user_ent_add(unsigned int ino, const char *process, int pid, int fd)
{
	struct user_ent *p, **pp;
	int str_len;

	str_len = strlen(process) + 1;
	p = malloc(sizeof(struct user_ent) + str_len);
	if (!p)
		abort();
	p->next = NULL;
	p->ino = ino;
	p->pid = pid;
	p->fd = fd;
	strcpy(p->process, process);

	pp = &user_ent_hash[user_ent_hashfn(ino)];
	p->next = *pp;
	*pp = p;
}

int find_users(unsigned ino, char *buf, int buflen)
{
	struct user_ent *p;
	int cnt = 0;
	char *ptr;

	if (!ino)
		return 0;

	p = user_ent_hash[user_ent_hashfn(ino)];
	ptr = buf;
	while (p) {
		if (p->ino != ino)
			goto next;

		if (ptr - buf >= buflen - 1)
			break;

		snprintf(ptr, buflen - (ptr - buf),
			 "(\"%s\",%d,%d),",
			 p->process, p->pid, p->fd);
		ptr += strlen(ptr);
		cnt++;

	next:
		p = p->next;
	}

	if (ptr != buf)
		ptr[-1] = '\0';

	return cnt;
}

/* Get stats from slab */

struct slabstat
{
	int socks;
	int tcp_ports;
	int tcp_tws;
	int tcp_syns;
	int skbs;
};

struct slabstat slabstat;

static const char *slabstat_ids[] =
{
	"sock",
	"tcp_bind_bucket",
	"tcp_tw_bucket",
	"tcp_open_request",
	"skbuff_head_cache",
};

int get_slabstat(struct slabstat *s)
{
	char buf[256];
	FILE *fp;
	int cnt;

	memset(s, 0, sizeof(*s));

	fp = slabinfo_open();
	if (!fp)
		return -1;

	cnt = sizeof(*s)/sizeof(int);

	fgets(buf, sizeof(buf), fp);
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int i;
		for (i=0; i<sizeof(slabstat_ids)/sizeof(slabstat_ids[0]); i++) {
			if (memcmp(buf, slabstat_ids[i], strlen(slabstat_ids[i])) == 0) {
				sscanf(buf, "%*s%d", ((int *)s) + i);
				cnt--;
				break;
			}
		}
		if (cnt <= 0)
			break;
	}

	fclose(fp);
	return 0;
}

static const char *sstate_name[] = {
	"UNKNOWN",
	[TCP_ESTABLISHED] = "ESTAB",
	[TCP_SYN_SENT] = "SYN-SENT",
	[TCP_SYN_RECV] = "SYN-RECV",
	[TCP_FIN_WAIT1] = "FIN-WAIT-1",
	[TCP_FIN_WAIT2] = "FIN-WAIT-2",
	[TCP_TIME_WAIT] = "TIME-WAIT",
	[TCP_CLOSE] = "UNCONN",
	[TCP_CLOSE_WAIT] = "CLOSE-WAIT",
	[TCP_LAST_ACK] = "LAST-ACK",
	[TCP_LISTEN] = 	"LISTEN",
	[TCP_CLOSING] = "CLOSING",
};

static const char *sstate_namel[] = {
	"UNKNOWN",
	[TCP_ESTABLISHED] = "established",
	[TCP_SYN_SENT] = "syn-sent",
	[TCP_SYN_RECV] = "syn-recv",
	[TCP_FIN_WAIT1] = "fin-wait-1",
	[TCP_FIN_WAIT2] = "fin-wait-2",
	[TCP_TIME_WAIT] = "time-wait",
	[TCP_CLOSE] = "unconnected",
	[TCP_CLOSE_WAIT] = "close-wait",
	[TCP_LAST_ACK] = "last-ack",
	[TCP_LISTEN] = 	"listening",
	[TCP_CLOSING] = "closing",
};

struct tcpstat
{
	inet_prefix	local;
	inet_prefix	remote;
	int		lport;
	int		rport;
	int		state;
	int		rq, wq;
	int		timer;
	int		timeout;
	int		retrs;
	unsigned	ino;
	int		probes;
	unsigned	uid;
	int		refcnt;
	unsigned long long sk;
	int		rto, ato, qack, cwnd, ssthresh;
};

static const char *tmr_name[] = {
	"off",
	"on",
	"keepalive",
	"timewait",
	"persist",
	"unknown"
};

const char *print_ms_timer(int timeout)
{
	static char buf[64];
	int secs, msecs, minutes;
	if (timeout < 0)
		timeout = 0;
	secs = timeout/1000;
	minutes = secs/60;
	secs = secs%60;
	msecs = timeout%1000;
	buf[0] = 0;
	if (minutes) {
		msecs = 0;
		snprintf(buf, sizeof(buf)-16, "%dmin", minutes);
		if (minutes > 9)
			secs = 0;
	}
	if (secs) {
		if (secs > 9)
			msecs = 0;
		sprintf(buf+strlen(buf), "%d%s", secs, msecs ? "." : "sec");
	}
	if (msecs)
		sprintf(buf+strlen(buf), "%03dms", msecs);
	return buf;
}

const char *print_hz_timer(int timeout)
{
	int hz = get_user_hz();
	return print_ms_timer(((timeout*1000) + hz-1)/hz);
}

struct scache
{
	struct scache *next;
	int port;
	char *name;
	const char *proto;
};

struct scache *rlist;

void init_service_resolver(void)
{
	char buf[128];
	FILE *fp = popen("/usr/sbin/rpcinfo -p 2>/dev/null", "r");
	if (fp) {
		fgets(buf, sizeof(buf), fp);
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			unsigned int progn, port;
			char proto[128], prog[128];
			if (sscanf(buf, "%u %*d %s %u %s", &progn, proto,
				   &port, prog+4) == 4) {
				struct scache *c = malloc(sizeof(*c));
				if (c) {
					c->port = port;
					memcpy(prog, "rpc.", 4);
					c->name = strdup(prog);
					if (strcmp(proto, TCP_PROTO) == 0)
						c->proto = TCP_PROTO;
					else if (strcmp(proto, UDP_PROTO) == 0)
						c->proto = UDP_PROTO;
					else
						c->proto = NULL;
					c->next = rlist;
					rlist = c;
				}
			}
		}
	}
}

static int ip_local_port_min, ip_local_port_max;

/* Even do not try default linux ephemeral port ranges:
 * default /etc/services contains so much of useless crap
 * wouldbe "allocated" to this area that resolution
 * is really harmful. I shrug each time when seeing
 * "socks" or "cfinger" in dumps.
 */
static int is_ephemeral(int port)
{
	if (!ip_local_port_min) {
		FILE *f = ephemeral_ports_open();
		if (f) {
			fscanf(f, "%d %d",
			       &ip_local_port_min, &ip_local_port_max);
			fclose(f);
		} else {
			ip_local_port_min = 1024;
			ip_local_port_max = 4999;
		}
	}

	return (port >= ip_local_port_min && port<= ip_local_port_max);
}


const char *__resolve_service(int port)
{
	struct scache *c;

	for (c = rlist; c; c = c->next) {
		if (c->port == port && c->proto == dg_proto)
			return c->name;
	}

	if (!is_ephemeral(port)) {
		static int notfirst;
		struct servent *se;
		if (!notfirst) {
			setservent(1);
			notfirst = 1;
		}
		se = getservbyport(htons(port), dg_proto);
		if (se)
			return se->s_name;
	}

	return NULL;
}


const char *resolve_service(int port)
{
	static char buf[128];
	static struct scache cache[256];

	if (port == 0) {
		buf[0] = '*';
		buf[1] = 0;
		return buf;
	}

	if (resolve_services) {
		if (dg_proto == RAW_PROTO) {
			return inet_proto_n2a(port, buf, sizeof(buf));
		} else {
			struct scache *c;
			const char *res;
			int hash = (port^(((unsigned long)dg_proto)>>2))&255;

			for (c = &cache[hash]; c; c = c->next) {
				if (c->port == port &&
				    c->proto == dg_proto) {
					if (c->name)
						return c->name;
					goto do_numeric;
				}
			}

			if ((res = __resolve_service(port)) != NULL) {
				if ((c = malloc(sizeof(*c))) == NULL)
					goto do_numeric;
			} else {
				c = &cache[hash];
				if (c->name)
					free(c->name);
			}
			c->port = port;
			c->name = NULL;
			c->proto = dg_proto;
			if (res) {
				c->name = strdup(res);
				c->next = cache[hash].next;
				cache[hash].next = c;
			}
			if (c->name)
				return c->name;
		}
	}

	do_numeric:
	sprintf(buf, "%u", port);
	return buf;
}

void formatted_print(const inet_prefix *a, int port)
{
	char buf[1024];
	const char *ap = buf;
	int est_len;

	est_len = addr_width;

	if (a->family == AF_INET) {
		if (a->data[0] == 0) {
			buf[0] = '*';
			buf[1] = 0;
		} else {
			ap = format_host(AF_INET, 4, a->data, buf, sizeof(buf));
		}
	} else {
		ap = format_host(a->family, 16, a->data, buf, sizeof(buf));
		est_len = strlen(ap);
		if (est_len <= addr_width)
			est_len = addr_width;
		else
			est_len = addr_width + ((est_len-addr_width+3)/4)*4;
	}
	printf("%*s:%-*s ", est_len, ap, serv_width, resolve_service(port));
}

struct aafilter
{
	inet_prefix	addr;
	int		port;
	struct aafilter *next;
};

int inet2_addr_match(const inet_prefix *a, const inet_prefix *p, int plen)
{
	if (!inet_addr_match(a, p, plen))
		return 0;

	/* Cursed "v4 mapped" addresses: v4 mapped socket matches
	 * pure IPv4 rule, but v4-mapped rule selects only v4-mapped
	 * sockets. Fair? */
	if (p->family == AF_INET && a->family == AF_INET6) {
		if (a->data[0] == 0 && a->data[1] == 0 &&
		    a->data[2] == htonl(0xffff)) {
			inet_prefix tmp = *a;
			tmp.data[0] = a->data[3];
			return inet_addr_match(&tmp, p, plen);
		}
	}
	return 1;
}

int unix_match(const inet_prefix *a, const inet_prefix *p)
{
	char *addr, *pattern;
	memcpy(&addr, a->data, sizeof(addr));
	memcpy(&pattern, p->data, sizeof(pattern));
	if (pattern == NULL)
		return 1;
	if (addr == NULL)
		addr = "";
	return !fnmatch(pattern, addr, 0);
}

int run_ssfilter(struct ssfilter *f, struct tcpstat *s)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
                static int low, high=65535;

		if (s->local.family == AF_UNIX) {
			char *p;
			memcpy(&p, s->local.data, sizeof(p));
			return p == NULL || (p[0] == '@' && strlen(p) == 6 &&
					     strspn(p+1, "0123456789abcdef") == 5);
		}
		if (s->local.family == AF_PACKET)
			return s->lport == 0 && s->local.data == 0;
		if (s->local.family == AF_NETLINK)
			return s->lport < 0;

                if (!low) {
			FILE *fp = ephemeral_ports_open();
			if (fp) {
				fscanf(fp, "%d%d", &low, &high);
				fclose(fp);
			}
		}
		return s->lport >= low && s->lport <= high;
	}
		case SSF_DCOND:
	{
		struct aafilter *a = (void*)f->pred;
		if (a->addr.family == AF_UNIX)
			return unix_match(&s->remote, &a->addr);
		if (a->port != -1 && a->port != s->rport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->remote, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_SCOND:
	{
		struct aafilter *a = (void*)f->pred;
		if (a->addr.family == AF_UNIX)
			return unix_match(&s->local, &a->addr);
		if (a->port != -1 && a->port != s->lport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->local, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_D_GE:
	{
		struct aafilter *a = (void*)f->pred;
		return s->rport >= a->port;
	}
		case SSF_D_LE:
	{
		struct aafilter *a = (void*)f->pred;
		return s->rport <= a->port;
	}
		case SSF_S_GE:
	{
		struct aafilter *a = (void*)f->pred;
		return s->lport >= a->port;
	}
		case SSF_S_LE:
	{
		struct aafilter *a = (void*)f->pred;
		return s->lport <= a->port;
	}

		/* Yup. It is recursion. Sorry. */
		case SSF_AND:
		return run_ssfilter(f->pred, s) && run_ssfilter(f->post, s);
		case SSF_OR:
		return run_ssfilter(f->pred, s) || run_ssfilter(f->post, s);
		case SSF_NOT:
		return !run_ssfilter(f->pred, s);
		default:
		abort();
	}
}

/* Relocate external jumps by reloc. */
static void ssfilter_patch(char *a, int len, int reloc)
{
	while (len > 0) {
		struct inet_diag_bc_op *op = (struct inet_diag_bc_op*)a;
		if (op->no == len+4)
			op->no += reloc;
		len -= op->yes;
		a += op->yes;
	}
	if (len < 0)
		abort();
}

static int ssfilter_bytecompile(struct ssfilter *f, char **bytecode)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
		if (!(*bytecode=malloc(4))) abort();
		((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
		return 8;
	}
		case SSF_DCOND:
		case SSF_SCOND:
	{
		struct aafilter *a = (void*)f->pred;
		struct aafilter *b;
		char *ptr;
		int  code = (f->type == SSF_DCOND ? INET_DIAG_BC_D_COND : INET_DIAG_BC_S_COND);
		int len = 0;

		for (b=a; b; b=b->next) {
			len += 4 + sizeof(struct inet_diag_hostcond);
			if (a->addr.family == AF_INET6)
				len += 16;
			else
				len += 4;
			if (b->next)
				len += 4;
		}
		if (!(ptr = malloc(len))) abort();
		*bytecode = ptr;
		for (b=a; b; b=b->next) {
			struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)ptr;
			int alen = (a->addr.family == AF_INET6 ? 16 : 4);
			int oplen = alen + 4 + sizeof(struct inet_diag_hostcond);
			struct inet_diag_hostcond *cond = (struct inet_diag_hostcond*)(ptr+4);

			*op = (struct inet_diag_bc_op){ code, oplen, oplen+4 };
			cond->family = a->addr.family;
			cond->port = a->port;
			cond->prefix_len = a->addr.bitlen;
			memcpy(cond->addr, a->addr.data, alen);
			ptr += oplen;
			if (b->next) {
				op = (struct inet_diag_bc_op *)ptr;
				*op = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, len - (ptr-*bytecode)};
				ptr += 4;
			}
		}
		return ptr - *bytecode;
	}
		case SSF_D_GE:
	{
		struct aafilter *x = (void*)f->pred;
		if (!(*bytecode=malloc(8))) abort();
		((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_GE, 8, 12 };
		((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_D_LE:
	{
		struct aafilter *x = (void*)f->pred;
		if (!(*bytecode=malloc(8))) abort();
		((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_LE, 8, 12 };
		((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_GE:
	{
		struct aafilter *x = (void*)f->pred;
		if (!(*bytecode=malloc(8))) abort();
		((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_GE, 8, 12 };
		((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_LE:
	{
		struct aafilter *x = (void*)f->pred;
		if (!(*bytecode=malloc(8))) abort();
		((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_LE, 8, 12 };
		((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}

		case SSF_AND:
	{
		char *a1, *a2, *a, l1, l2;
		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!(a = malloc(l1+l2))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1, a2, l2);
		free(a1); free(a2);
		ssfilter_patch(a, l1, l2);
		*bytecode = a;
		return l1+l2;
	}
		case SSF_OR:
	{
		char *a1, *a2, *a, l1, l2;
		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!(a = malloc(l1+l2+4))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1+4, a2, l2);
		free(a1); free(a2);
		*(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, l2+4 };
		*bytecode = a;
		return l1+l2+4;
	}
		case SSF_NOT:
	{
		char *a1, *a, l1;
		l1 = ssfilter_bytecompile(f->pred, &a1);
		if (!(a = malloc(l1+4))) abort();
		memcpy(a, a1, l1);
		free(a1);
		*(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, 8 };
		*bytecode = a;
		return l1+4;
	}
		default:
		abort();
	}
}

static int remember_he(struct aafilter *a, struct hostent *he)
{
	char **ptr = he->h_addr_list;
	int cnt = 0;
	int len;

	if (he->h_addrtype == AF_INET)
		len = 4;
	else if (he->h_addrtype == AF_INET6)
		len = 16;
	else
		return 0;

	while (*ptr) {
		struct aafilter *b = a;
		if (a->addr.bitlen) {
			if ((b = malloc(sizeof(*b))) == NULL)
				return cnt;
			*b = *a;
			b->next = a->next;
			a->next = b;
		}
		memcpy(b->addr.data, *ptr, len);
		b->addr.bytelen = len;
		b->addr.bitlen = len*8;
		b->addr.family = he->h_addrtype;
		ptr++;
		cnt++;
	}
	return cnt;
}

static int get_dns_host(struct aafilter *a, const char *addr, int fam)
{
	static int notfirst;
	int cnt = 0;
	struct hostent *he;

	a->addr.bitlen = 0;
	if (!notfirst) {
		sethostent(1);
		notfirst = 1;
	}
	he = gethostbyname2(addr, fam == AF_UNSPEC ? AF_INET : fam);
	if (he)
		cnt = remember_he(a, he);
	if (fam == AF_UNSPEC) {
		he = gethostbyname2(addr, AF_INET6);
		if (he)
			cnt += remember_he(a, he);
	}
	return !cnt;
}

static int xll_initted = 0;

static void xll_init(void)
{
	struct rtnl_handle rth;
	rtnl_open(&rth, 0);
	ll_init_map(&rth);
	rtnl_close(&rth);
	xll_initted = 1;
}

static const char *xll_index_to_name(int index)
{
	if (!xll_initted)
		xll_init();
	return ll_index_to_name(index);
}

static int xll_name_to_index(const char *dev)
{
	if (!xll_initted)
		xll_init();
	return ll_name_to_index(dev);
}

void *parse_hostcond(char *addr)
{
	char *port = NULL;
	struct aafilter a;
	struct aafilter *res;
	int fam = preferred_family;

	memset(&a, 0, sizeof(a));
	a.port = -1;

	if (fam == AF_UNIX || strncmp(addr, "unix:", 5) == 0) {
		char *p;
		a.addr.family = AF_UNIX;
		if (strncmp(addr, "unix:", 5) == 0)
			addr+=5;
		p = strdup(addr);
		a.addr.bitlen = 8*strlen(p);
		memcpy(a.addr.data, &p, sizeof(p));
		goto out;
	}

	if (fam == AF_PACKET || strncmp(addr, "link:", 5) == 0) {
		a.addr.family = AF_PACKET;
		a.addr.bitlen = 0;
		if (strncmp(addr, "link:", 5) == 0)
			addr+=5;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if ((a.port = xll_name_to_index(port+1)) <= 0)
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			unsigned short tmp;
			a.addr.bitlen = 32;
			if (ll_proto_a2n(&tmp, addr))
				return NULL;
			a.addr.data[0] = ntohs(tmp);
		}
		goto out;
	}

	if (fam == AF_NETLINK || strncmp(addr, "netlink:", 8) == 0) {
		a.addr.family = AF_NETLINK;
		a.addr.bitlen = 0;
		if (strncmp(addr, "netlink:", 8) == 0)
			addr+=8;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if (strcmp(port+1, "kernel") == 0)
						a.port = 0;
					else
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			a.addr.bitlen = 32;
			if (get_u32(a.addr.data, addr, 0)) {
				if (strcmp(addr, "rtnl") == 0)
					a.addr.data[0] = 0;
				else if (strcmp(addr, "fw") == 0)
					a.addr.data[0] = 3;
				else if (strcmp(addr, "tcpdiag") == 0)
					a.addr.data[0] = 4;
				else
					return NULL;
			}
		}
		goto out;
	}

	if (strncmp(addr, "inet:", 5) == 0) {
		addr += 5;
		fam = AF_INET;
	} else if (strncmp(addr, "inet6:", 6) == 0) {
		addr += 6;
		fam = AF_INET6;
	}

	/* URL-like literal [] */
	if (addr[0] == '[') {
		addr++;
		if ((port = strchr(addr, ']')) == NULL)
			return NULL;
		*port++ = 0;
	} else if (addr[0] == '*') {
		port = addr+1;
	} else {
		port = strrchr(strchr(addr, '/') ? : addr, ':');
	}
	if (port && *port) {
		if (*port != ':')
			return NULL;
		*port++ = 0;
		if (*port && *port != '*') {
			if (get_integer(&a.port, port, 0)) {
				struct servent *se1 = NULL;
				struct servent *se2 = NULL;
				if (current_filter.dbs&(1<<UDP_DB))
					se1 = getservbyname(port, UDP_PROTO);
				if (current_filter.dbs&(1<<TCP_DB))
					se2 = getservbyname(port, TCP_PROTO);
				if (se1 && se2 && se1->s_port != se2->s_port) {
					fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
					return NULL;
				}
				if (!se1)
					se1 = se2;
				if (se1) {
					a.port = ntohs(se1->s_port);
				} else {
					struct scache *s;
					for (s = rlist; s; s = s->next) {
						if ((s->proto == UDP_PROTO &&
						     (current_filter.dbs&(1<<UDP_DB))) ||
						    (s->proto == TCP_PROTO &&
						     (current_filter.dbs&(1<<TCP_DB)))) {
							if (s->name && strcmp(s->name, port) == 0) {
								if (a.port > 0 && a.port != s->port) {
									fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
									return NULL;
								}
								a.port = s->port;
							}
						}
					}
					if (a.port <= 0) {
						fprintf(stderr, "Error: \"%s\" does not look like a port.\n", port);
						return NULL;
					}
				}
			}
		}
	}
	if (addr && *addr && *addr != '*') {
		if (get_prefix_1(&a.addr, addr, fam)) {
			if (get_dns_host(&a, addr, fam)) {
				fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", addr);
				return NULL;
			}
		}
	}

	out:
	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

static int generic_record_read(FILE *fp,
			       int (*worker)(char*, const struct filter *, int),
			       const struct filter *f, int fam)
{
	char line[256];

	/* skip header */
	if (fgets(line, sizeof(line), fp) == NULL)
		goto outerr;

	while (fgets(line, sizeof(line), fp) != NULL) {
		int n = strlen(line);
		if (n == 0 || line[n-1] != '\n') {
			errno = -EINVAL;
			return -1;
		}
		line[n-1] = 0;

		if (worker(line, f, fam) < 0)
			return 0;
	}
outerr:

	return ferror(fp) ? -1 : 0;
}

/*main parse function*/
static int tcp_show_sock(struct nlmsghdr *nlh, struct filter *f)
{
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

#ifdef DEBUGG
		vtun_syslog(LOG_INFO, "fss all conns send_q - %i recv_q - %i lport - %i rport - %i", r->idiag_wqueue, r->idiag_rqueue, s.lport, s.rport);
#endif
		// fill channel_info structure
    if (conn_counter < channel_amount_ss) {
        for (int i = 0; i < channel_amount_ss; i++) {
            if ((channel_info_ss[i]->lport == ntohs(r->id.idiag_sport)) | (channel_info_ss[i]->rport == ntohs(r->id.idiag_dport))) {
                format_info(nlh, r);
                channel_info_ss[i]->recv_q = r->idiag_rqueue;
                channel_info_ss[i]->send_q = r->idiag_wqueue;
#ifdef DEBUGG
                vtun_syslog(LOG_INFO, "fss conn_counter - %i channel_amount_ss - %i send_q - %i recv_q - %i lport - %i rport - %i", i, channel_amount_ss,
                        channel_info_ss[i]->send_q, channel_info_ss[i]->recv_q, s.lport, s.rport);
#endif
                conn_counter++;
                break;
            }
        }
    }

	return 0;
}

/**
 * Function for connect to kernel's netlink interface
 * and get info about tcp connections
 *
 * @param f - flags for getting tcp information
 * @param dump_fp - now unused
 * @param socktype
 * @return
 */
static int tcp_show_netlink(struct filter *f, FILE *dump_fp, int socktype)
{
	int fd;
	struct sockaddr_nl nladdr;
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req r;
	} req;
	char    *bc = NULL;
	int	bclen;
	struct msghdr msg;
	struct rtattr rta;
	char	buf[8192];
	struct iovec iov[3];

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0) {
		int errsv = errno;
		switch (errno) {
		case EMFILE:
			printf("Too many open files.\n");
			break;
		default:
			printf("Error: %d.\n", errsv);
		}
		return -1;
	}


	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = socktype;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 123456;
	memset(&req.r, 0, sizeof(req.r));
	req.r.idiag_family = AF_INET;
	req.r.idiag_states = f->states;
	if (show_mem)
		req.r.idiag_ext |= (1<<(INET_DIAG_MEMINFO-1));

	if (show_tcpinfo) {
		req.r.idiag_ext |= (1<<(INET_DIAG_INFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_CONG-1));
	}

	iov[0] = (struct iovec){
		.iov_base = &req,
		.iov_len = sizeof(req)
	};
	if (f->f) {
		bclen = ssfilter_bytecompile(f->f, &bc);
		rta.rta_type = INET_DIAG_REQ_BYTECODE;
		rta.rta_len = RTA_LENGTH(bclen);
		iov[1] = (struct iovec){ &rta, sizeof(rta) };
		iov[2] = (struct iovec){ bc, bclen };
		req.nlh.nlmsg_len += RTA_LENGTH(bclen);
	}

	msg = (struct msghdr) {
		.msg_name = (void*)&nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = f->f ? 3 : 1,
	};

	if (sendmsg(fd, &msg, 0) < 0)
		return -1;

	iov[0] = (struct iovec){
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
			printf("TIMESTAMP\n");
			printf("mono\t%ld\t%ld\n", ts_mono.tv_sec, ts_mono.tv_nsec);
			printf("real\t%ld\t%ld\n", ts_rt.tv_sec, ts_rt.tv_nsec);

	while (1) {
		int status;
		struct nlmsghdr *h;

		msg = (struct msghdr) {
			(void*)&nladdr, sizeof(nladdr),
			iov,	1,
			NULL,	0,
			0
		};

		status = recvmsg(fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			perror("OVERRUN");
			continue;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return 0;
		}

		if (dump_fp)
			fwrite(buf, 1, NLMSG_ALIGN(status), dump_fp);

		h = (struct nlmsghdr*)buf;
		while (NLMSG_OK(h, status)) {
			// TODO(tierney): Record the time here, when we reeive the message.
			clock_gettime(CLOCK_MONOTONIC_RAW, &ts_mono);
			clock_gettime(CLOCK_REALTIME, &ts_rt);

			int err;
			struct inet_diag_msg *r = NLMSG_DATA(h);

			if (/*h->nlmsg_pid != rth->local.nl_pid ||*/
			    h->nlmsg_seq != 123456)
				goto skip_it;

			if (h->nlmsg_type == NLMSG_DONE) {
				close(fd);
				return 0;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
					fprintf(stderr, "ERROR truncated\n");
				} else {
					errno = -err->error;
					perror("TCPDIAG answers");
				}
				return 0;
			}
			if (!dump_fp) {
				if (!(f->families & (1<<r->idiag_family))) {
					h = NLMSG_NEXT(h, status);
					continue;
				}
				err = tcp_show_sock(h, NULL);
				if (err < 0)
					return err;
			}

skip_it:
			h = NLMSG_NEXT(h, status);
		}
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
	if (close(fd) == -1) {
		printf("Unable to close socket: %d\n.", errno);
	}
	return 0;
}

int dgram_show_line(char *line, const struct filter *f, int family)
{
	struct tcpstat s;
	char *loc, *rem, *data;
	char opt[256];
	int n;
	char *p;

	if ((p = strchr(line, ':')) == NULL)
		return -1;
	loc = p+2;

	if ((p = strchr(loc, ':')) == NULL)
		return -1;
	p[5] = 0;
	rem = p+6;

	if ((p = strchr(rem, ':')) == NULL)
		return -1;
	p[5] = 0;
	data = p+6;

	do {
		int state = (data[1] >= 'A') ? (data[1] - 'A' + 10) : (data[1] - '0');

		if (!(f->states & (1<<state)))
			return 0;
	} while (0);

	s.local.family = s.remote.family = family;
	if (family == AF_INET) {
		sscanf(loc, "%x:%x", s.local.data, (unsigned*)&s.lport);
		sscanf(rem, "%x:%x", s.remote.data, (unsigned*)&s.rport);
		s.local.bytelen = s.remote.bytelen = 4;
	} else {
		sscanf(loc, "%08x%08x%08x%08x:%x",
		       s.local.data,
		       s.local.data+1,
		       s.local.data+2,
		       s.local.data+3,
		       &s.lport);
		sscanf(rem, "%08x%08x%08x%08x:%x",
		       s.remote.data,
		       s.remote.data+1,
		       s.remote.data+2,
		       s.remote.data+3,
		       &s.rport);
		s.local.bytelen = s.remote.bytelen = 16;
	}

	if (f->f && run_ssfilter(f->f, &s) == 0)
		return 0;

	opt[0] = 0;
	n = sscanf(data, "%x %x:%x %*x:%*x %*x %d %*d %u %d %llx %[^\n]\n",
	       &s.state, &s.wq, &s.rq,
	       &s.uid, &s.ino,
	       &s.refcnt, &s.sk, opt);

	if (n < 9)
		opt[0] = 0;



	if (netid_width)
		printf("%-*s ", netid_width, dg_proto);
	if (state_width)
		printf("%-*s ", state_width, sstate_name[s.state]);

	printf("%-6d %-6d ", s.rq, s.wq);

	formatted_print(&s.local, s.lport);
	formatted_print(&s.remote, s.rport);

	if (show_users) {
		char ubuf[4096];
		if (find_users(s.ino, ubuf, sizeof(ubuf)) > 0)
			printf(" users:(%s)", ubuf);
	}

	if (show_details) {
		if (s.uid)
			printf(" uid=%u", (unsigned)s.uid);
		printf(" ino=%u", s.ino);
		printf(" sk=%llx", s.sk);
		if (opt[0])
			printf(" opt:\"%s\"", opt);
	}
	printf("\n");

	return 0;
}


int udp_show(struct filter *f)
{
	FILE *fp = NULL;

	dg_proto = UDP_PROTO;

	if (f->families&(1<<AF_INET)) {
		if ((fp = net_udp_open()) == NULL)
			goto outerr;
		if (generic_record_read(fp, dgram_show_line, f, AF_INET))
			goto outerr;
		fclose(fp);
	}

	if ((f->families&(1<<AF_INET6)) &&
	    (fp = net_udp6_open()) != NULL) {
		if (generic_record_read(fp, dgram_show_line, f, AF_INET6))
			goto outerr;
		fclose(fp);
	}
	return 0;

outerr:
	do {
		int saved_errno = errno;
		if (fp)
			fclose(fp);
		errno = saved_errno;
		return -1;
	} while (0);
}

int raw_show(struct filter *f)
{
	FILE *fp = NULL;

	dg_proto = RAW_PROTO;

	if (f->families&(1<<AF_INET)) {
		if ((fp = net_raw_open()) == NULL)
			goto outerr;
		if (generic_record_read(fp, dgram_show_line, f, AF_INET))
			goto outerr;
		fclose(fp);
	}

	if ((f->families&(1<<AF_INET6)) &&
	    (fp = net_raw6_open()) != NULL) {
		if (generic_record_read(fp, dgram_show_line, f, AF_INET6))
			goto outerr;
		fclose(fp);
	}
	return 0;

outerr:
	do {
		int saved_errno = errno;
		if (fp)
			fclose(fp);
		errno = saved_errno;
		return -1;
	} while (0);
}


struct unixstat
{
	struct unixstat *next;
	int ino;
	int peer;
	int rq;
	int wq;
	int state;
	int type;
	char *name;
};



int unix_state_map[] = { SS_CLOSE, SS_SYN_SENT,
			 SS_ESTABLISHED, SS_CLOSING };


#define MAX_UNIX_REMEMBER (1024*1024/sizeof(struct unixstat))

void unix_list_free(struct unixstat *list)
{
	while (list) {
		struct unixstat *s = list;
		list = list->next;
		if (s->name)
			free(s->name);
		free(s);
	}
}

void unix_list_print(struct unixstat *list, struct filter *f)
{
	struct unixstat *s;
	char *peer;

	for (s = list; s; s = s->next) {
		if (!(f->states & (1<<s->state)))
			continue;
		if (s->type == SOCK_STREAM && !(f->dbs&(1<<UNIX_ST_DB)))
			continue;
		if (s->type == SOCK_DGRAM && !(f->dbs&(1<<UNIX_DG_DB)))
			continue;

		peer = "*";
		if (s->peer) {
			struct unixstat *p;
			for (p = list; p; p = p->next) {
				if (s->peer == p->ino)
					break;
			}
			if (!p) {
				peer = "?";
			} else {
				peer = p->name ? : "*";
			}
		}

		if (f->f) {
			struct tcpstat tst;
			tst.local.family = AF_UNIX;
			tst.remote.family = AF_UNIX;
			memcpy(tst.local.data, &s->name, sizeof(s->name));
			if (strcmp(peer, "*") == 0)
				memset(tst.remote.data, 0, sizeof(peer));
			else
				memcpy(tst.remote.data, &peer, sizeof(peer));
			if (run_ssfilter(f->f, &tst) == 0)
				continue;
		}

		if (netid_width)
			printf("%-*s ", netid_width,
			       s->type == SOCK_STREAM ? "u_str" : "u_dgr");

		if (state_width)
			printf("%-*s ", state_width, sstate_name[s->state]);
		printf("%-6d %-6d ", s->rq, s->wq);
		printf("%*s %-*d %*s %-*d",
		       addr_width, s->name ? : "*", serv_width, s->ino,
		       addr_width, peer, serv_width, s->peer);
		if (show_users) {
			char ubuf[4096];
			if (find_users(s->ino, ubuf, sizeof(ubuf)) > 0)
				printf(" users:(%s)", ubuf);
		}
		printf("\n");
	}
}

int unix_show(struct filter *f)
{
	FILE *fp;
	char buf[256];
	char name[128];
	int  newformat = 0;
	int  cnt;
	struct unixstat *list = NULL;

	if ((fp = net_unix_open()) == NULL)
		return -1;
	fgets(buf, sizeof(buf)-1, fp);

	if (memcmp(buf, "Peer", 4) == 0)
		newformat = 1;
	cnt = 0;

	while (fgets(buf, sizeof(buf)-1, fp)) {
		struct unixstat *u, **insp;
		int flags;

		if (!(u = malloc(sizeof(*u))))
			break;
		u->name = NULL;

		if (sscanf(buf, "%x: %x %x %x %x %x %d %s",
			   &u->peer, &u->rq, &u->wq, &flags, &u->type,
			   &u->state, &u->ino, name) < 8)
			name[0] = 0;

		if (flags&(1<<16)) {
			u->state = SS_LISTEN;
		} else {
			u->state = unix_state_map[u->state-1];
			if (u->type == SOCK_DGRAM &&
			    u->state == SS_CLOSE &&
			    u->peer)
				u->state = SS_ESTABLISHED;
		}

		if (!newformat) {
			u->peer = 0;
			u->rq = 0;
			u->wq = 0;
		}

		insp = &list;
		while (*insp) {
			if (u->type < (*insp)->type ||
			    (u->type == (*insp)->type &&
			     u->ino < (*insp)->ino))
				break;
			insp = &(*insp)->next;
		}
		u->next = *insp;
		*insp = u;

		if (name[0]) {
			if ((u->name = malloc(strlen(name)+1)) == NULL)
				break;
			strcpy(u->name, name);
		}
		if (++cnt > MAX_UNIX_REMEMBER) {
			unix_list_print(list, f);
			unix_list_free(list);
			list = NULL;
			cnt = 0;
		}
	}

	if (list) {
		unix_list_print(list, f);
		unix_list_free(list);
		list = NULL;
		cnt = 0;
	}

	return 0;
}


int packet_show(struct filter *f)
{
	FILE *fp;
	char buf[256];
	int type;
	int prot;
	int iface;
	int state;
	int rq;
	int uid;
	int ino;
	unsigned long long sk;

	if (!(f->states & (1<<SS_CLOSE)))
		return 0;

	if ((fp = net_packet_open()) == NULL)
		return -1;
	fgets(buf, sizeof(buf)-1, fp);

	while (fgets(buf, sizeof(buf)-1, fp)) {
		sscanf(buf, "%llx %*d %d %x %d %d %u %u %u",
		       &sk,
		       &type, &prot, &iface, &state,
		       &rq, &uid, &ino);

		if (type == SOCK_RAW && !(f->dbs&(1<<PACKET_R_DB)))
			continue;
		if (type == SOCK_DGRAM && !(f->dbs&(1<<PACKET_DG_DB)))
			continue;
		if (f->f) {
			struct tcpstat tst;
			tst.local.family = AF_PACKET;
			tst.remote.family = AF_PACKET;
			tst.rport = 0;
			tst.lport = iface;
			tst.local.data[0] = prot;
			tst.remote.data[0] = 0;
			if (run_ssfilter(f->f, &tst) == 0)
				continue;
		}

		if (netid_width)
			printf("%-*s ", netid_width,
			       type == SOCK_RAW ? "p_raw" : "p_dgr");
		if (state_width)
			printf("%-*s ", state_width, "UNCONN");
		printf("%-6d %-6d ", rq, 0);
		if (prot == 3) {
			printf("%*s:", addr_width, "*");
		} else {
			char tb[16];
			printf("%*s:", addr_width,
			       ll_proto_n2a(htons(prot), tb, sizeof(tb)));
		}
		if (iface == 0) {
			printf("%-*s ", serv_width, "*");
		} else {
			printf("%-*s ", serv_width, xll_index_to_name(iface));
		}
		printf("%*s*%-*s",
		       addr_width, "", serv_width, "");

		if (show_users) {
			char ubuf[4096];
			if (find_users(ino, ubuf, sizeof(ubuf)) > 0)
				printf(" users:(%s)", ubuf);
		}
		if (show_details) {
			printf(" ino=%u uid=%u sk=%llx", ino, uid, sk);
		}
		printf("\n");
	}

	return 0;
}

int netlink_show(struct filter *f)
{
	FILE *fp;
	char buf[256];
	int prot, pid;
	unsigned groups;
	int rq, wq, rc;
	unsigned long long sk, cb;

	if (!(f->states & (1<<SS_CLOSE)))
		return 0;

	if ((fp = net_netlink_open()) == NULL)
		return -1;
	fgets(buf, sizeof(buf)-1, fp);

	while (fgets(buf, sizeof(buf)-1, fp)) {
		sscanf(buf, "%llx %d %d %x %d %d %llx %d",
		       &sk,
		       &prot, &pid, &groups, &rq, &wq, &cb, &rc);

		if (f->f) {
			struct tcpstat tst;
			tst.local.family = AF_NETLINK;
			tst.remote.family = AF_NETLINK;
			tst.rport = -1;
			tst.lport = pid;
			tst.local.data[0] = prot;
			tst.remote.data[0] = 0;
			if (run_ssfilter(f->f, &tst) == 0)
				continue;
		}

		if (netid_width)
			printf("%-*s ", netid_width, "nl");
		if (state_width)
			printf("%-*s ", state_width, "UNCONN");
		printf("%-6d %-6d ", rq, wq);
		if (resolve_services && prot == 0)
			printf("%*s:", addr_width, "rtnl");
		else if (resolve_services && prot == 3)
			printf("%*s:", addr_width, "fw");
		else if (resolve_services && prot == 4)
			printf("%*s:", addr_width, "tcpdiag");
		else
			printf("%*d:", addr_width, prot);
		if (pid == -1) {
			printf("%-*s ", serv_width, "*");
		} else if (resolve_services) {
			int done = 0;
			if (!pid) {
				done = 1;
				printf("%-*s ", serv_width, "kernel");
			} else if (pid > 0) {
				char procname[64];
				FILE *fp;
				sprintf(procname, "%s/%d/stat",
					getenv("PROC_ROOT") ? : "/proc", pid);
				if ((fp = fopen(procname, "r")) != NULL) {
					if (fscanf(fp, "%*d (%[^)])", procname) == 1) {
						sprintf(procname+strlen(procname), "/%d", pid);
						printf("%-*s ", serv_width, procname);
						done = 1;
					}
					fclose(fp);
				}
			}
			if (!done)
				printf("%-*d ", serv_width, pid);
		} else {
			printf("%-*d ", serv_width, pid);
		}
		printf("%*s*%-*s",
		       addr_width, "", serv_width, "");

		if (show_details) {
			printf(" sk=%llx cb=%llx groups=0x%08x", sk, cb, groups);
		}
		printf("\n");
	}

	return 0;
}

struct snmpstat
{
	int tcp_estab;
};

int get_snmp_int(char *proto, char *key, int *result)
{
	char buf[1024];
	FILE *fp;
	int protolen = strlen(proto);
	int keylen = strlen(key);

	*result = 0;

	if ((fp = net_snmp_open()) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p = buf;
		int  pos = 0;
		if (memcmp(buf, proto, protolen))
			continue;
		while ((p = strchr(p, ' ')) != NULL) {
			pos++;
			p++;
			if (memcmp(p, key, keylen) == 0 &&
			    (p[keylen] == ' ' || p[keylen] == '\n'))
				break;
		}
		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;
		if (memcmp(buf, proto, protolen))
			break;
		p = buf;
		while ((p = strchr(p, ' ')) != NULL) {
			p++;
			if (--pos == 0) {
				sscanf(p, "%d", result);
				fclose(fp);
				return 0;
			}
		}
	}

	fclose(fp);
	errno = ESRCH;
	return -1;
}


/* Get stats from sockstat */

struct sockstat
{
	int socks;
	int tcp_mem;
	int tcp_total;
	int tcp_orphans;
	int tcp_tws;
	int tcp4_hashed;
	int udp4;
	int raw4;
	int frag4;
	int frag4_mem;
	int tcp6_hashed;
	int udp6;
	int raw6;
	int frag6;
	int frag6_mem;
};

static void get_sockstat_line(char *line, struct sockstat *s)
{
	char id[256], rem[256];

	if (sscanf(line, "%[^ ] %[^\n]\n", id, rem) != 2)
		return;

	if (strcmp(id, "sockets:") == 0)
		sscanf(rem, "%*s%d", &s->socks);
	else if (strcmp(id, "UDP:") == 0)
		sscanf(rem, "%*s%d", &s->udp4);
	else if (strcmp(id, "UDP6:") == 0)
		sscanf(rem, "%*s%d", &s->udp6);
	else if (strcmp(id, "RAW:") == 0)
		sscanf(rem, "%*s%d", &s->raw4);
	else if (strcmp(id, "RAW6:") == 0)
		sscanf(rem, "%*s%d", &s->raw6);
	else if (strcmp(id, "TCP6:") == 0)
		sscanf(rem, "%*s%d", &s->tcp6_hashed);
	else if (strcmp(id, "FRAG:") == 0)
		sscanf(rem, "%*s%d%*s%d", &s->frag4, &s->frag4_mem);
	else if (strcmp(id, "FRAG6:") == 0)
		sscanf(rem, "%*s%d%*s%d", &s->frag6, &s->frag6_mem);
	else if (strcmp(id, "TCP:") == 0)
		sscanf(rem, "%*s%d%*s%d%*s%d%*s%d%*s%d",
		       &s->tcp4_hashed,
		       &s->tcp_orphans, &s->tcp_tws, &s->tcp_total, &s->tcp_mem);
}

int get_sockstat(struct sockstat *s)
{
	char buf[256];
	FILE *fp;

	memset(s, 0, sizeof(*s));

	if ((fp = net_sockstat_open()) == NULL)
		return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL)
		get_sockstat_line(buf, s);
	fclose(fp);

	if ((fp = net_sockstat6_open()) == NULL)
		return 0;
	while(fgets(buf, sizeof(buf), fp) != NULL)
		get_sockstat_line(buf, s);
	fclose(fp);

	return 0;
}

int print_summary(void)
{
	struct sockstat s;
	struct snmpstat sn;

	if (get_sockstat(&s) < 0)
		perror("ss: get_sockstat");
	if (get_snmp_int("Tcp:", "CurrEstab", &sn.tcp_estab) < 0)
		perror("ss: get_snmpstat");

	printf("Total: %d (kernel %d)\n", s.socks, slabstat.socks);

	printf("TCP:   %d (estab %d, closed %d, orphaned %d, synrecv %d, timewait %d/%d), ports %d\n",
	       s.tcp_total + slabstat.tcp_syns + s.tcp_tws,
	       sn.tcp_estab,
	       s.tcp_total - (s.tcp4_hashed+s.tcp6_hashed-s.tcp_tws),
	       s.tcp_orphans,
	       slabstat.tcp_syns,
	       s.tcp_tws, slabstat.tcp_tws,
	       slabstat.tcp_ports
	       );

	printf("\n");
	printf("Transport Total     IP        IPv6\n");
	printf("*	  %-9d %-9s %-9s\n", slabstat.socks, "-", "-");
	printf("RAW	  %-9d %-9d %-9d\n", s.raw4+s.raw6, s.raw4, s.raw6);
	printf("UDP	  %-9d %-9d %-9d\n", s.udp4+s.udp6, s.udp4, s.udp6);
	printf("TCP	  %-9d %-9d %-9d\n", s.tcp4_hashed+s.tcp6_hashed, s.tcp4_hashed, s.tcp6_hashed);
	printf("INET	  %-9d %-9d %-9d\n",
	       s.raw4+s.udp4+s.tcp4_hashed+
	       s.raw6+s.udp6+s.tcp6_hashed,
	       s.raw4+s.udp4+s.tcp4_hashed,
	       s.raw6+s.udp6+s.tcp6_hashed);
	printf("FRAG	  %-9d %-9d %-9d\n", s.frag4+s.frag6, s.frag4, s.frag6);

	printf("\n");

	return 0;
}

static void _usage(FILE *dest)
{
	fprintf(dest,
"Usage: ss [ OPTIONS ]\n"
"       ss [ OPTIONS ] [ FILTER ]\n"
"   -g, --continuous     continuous display data\n"
"   -h, --help		this message\n"
"   -V, --version	output version information\n"
"   -n, --numeric	don't resolve service names\n"
"   -r, --resolve       resolve host names\n"
"   -a, --all		display all sockets\n"
"   -l, --listening	display listening sockets\n"
"   -o, --options       show timer information\n"
"   -e, --extended      show detailed socket information\n"
"   -m, --memory        show socket memory usage\n"
"   -p, --processes	show process using socket\n"
"   -i, --info		show internal TCP information\n"
"   -s, --summary	show socket usage summary\n"
"\n"
"   -4, --ipv4          display only IP version 4 sockets\n"
"   -6, --ipv6          display only IP version 6 sockets\n"
"   -0, --packet	display PACKET sockets\n"
"   -t, --tcp		display only TCP sockets\n"
"   -u, --udp		display only UDP sockets\n"
"   -d, --dccp		display only DCCP sockets\n"
"   -w, --raw		display only RAW sockets\n"
"   -x, --unix		display only Unix domain sockets\n"
"   -f, --family=FAMILY display sockets of type FAMILY\n"
"\n"
"   -A, --query=QUERY\n"
"       QUERY := {all|inet|tcp|udp|raw|unix|packet|netlink}[,QUERY]\n"
"\n"
"   -F, --filter=FILE   read filter information from FILE\n"
"       FILTER := [ state TCP-STATE ] [ EXPRESSION ]\n"
		);
}

static void help(void) __attribute__((noreturn));
static void help(void)
{
	_usage(stdout);
	exit(0);
}

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	_usage(stderr);
	exit(-1);
}


int scan_state(const char *state)
{
	int i;
	if (strcasecmp(state, "close") == 0 ||
	    strcasecmp(state, "closed") == 0)
		return (1<<SS_CLOSE);
	if (strcasecmp(state, "syn-rcv") == 0)
		return (1<<SS_SYN_RECV);
	if (strcasecmp(state, "established") == 0)
		return (1<<SS_ESTABLISHED);
	if (strcasecmp(state, "all") == 0)
		return SS_ALL;
	if (strcasecmp(state, "connected") == 0)
		return SS_ALL & ~((1<<SS_CLOSE)|(1<<SS_LISTEN));
	if (strcasecmp(state, "synchronized") == 0)
		return SS_ALL & ~((1<<SS_CLOSE)|(1<<SS_LISTEN)|(1<<SS_SYN_SENT));
	if (strcasecmp(state, "bucket") == 0)
		return (1<<SS_SYN_RECV)|(1<<SS_TIME_WAIT);
	if (strcasecmp(state, "big") == 0)
		return SS_ALL & ~((1<<SS_SYN_RECV)|(1<<SS_TIME_WAIT));
	for (i=0; i<SS_MAX; i++) {
		if (strcasecmp(state, sstate_namel[i]) == 0)
			return (1<<i);
	}
	return 0;
}

static const struct option long_opts[] = {
	{ "numeric", 0, 0, 'n' },
	{ "resolve", 0, 0, 'r' },
	{ "options", 0, 0, 'o' },
	{ "extended", 0, 0, 'e' },
	{ "memory", 0, 0, 'm' },
	{ "info", 0, 0, 'i' },
	{ "processes", 0, 0, 'p' },
	{ "dccp", 0, 0, 'd' },
	{ "tcp", 0, 0, 't' },
	{ "udp", 0, 0, 'u' },
	{ "raw", 0, 0, 'w' },
	{ "unix", 0, 0, 'x' },
	{ "all", 0, 0, 'a' },
	{ "listening", 0, 0, 'l' },
	{ "ipv4", 0, 0, '4' },
	{ "ipv6", 0, 0, '6' },
	{ "packet", 0, 0, '0' },
	{ "family", 1, 0, 'f' },
	{ "socket", 1, 0, 'A' },
	{ "summary", 0, 0, 's' },
	{ "diag", 0, 0, 'D' },
	{ "filter", 1, 0, 'F' },
	{ "version", 0, 0, 'V' },
	{ "help", 0, 0, 'h' },
	{ 0 }

};

/**
 * Function get from **channel_info_vt port's num and fill information about tcp connection
 * @param channel_info_vt
 * @param channel_amount - *channel_info_vt[] array length
 */
void get_format_tcp_info(struct channel_info** channel_info_vt, int channel_amount) {
    channel_info_ss = channel_info_vt;
    channel_amount_ss = channel_amount;
    conn_counter = 0;
    show_tcpinfo = 1;

    memset(&current_filter, 0, sizeof(current_filter));

    current_filter.states = default_filter.states;
    current_filter.dbs = default_filter.dbs;
    current_filter.families = default_filter.families;

    tcp_show_netlink(&current_filter, NULL, TCPDIAG_GETSOCK);

#ifdef DEBUGG
    for (int i = 0; i < channel_amount; i++) {
        vtun_syslog(LOG_INFO, "fss channel_info_vt send_q %u lport - %i rport - %i", channel_info_vt[i]->send_q, channel_info_vt[i]->lport, channel_info_vt[i]->rport);
        vtun_syslog(LOG_INFO, "fss channel_info_ss send_q %u lport - %i rport - %i", channel_info_ss[i]->send_q, channel_info_ss[i]->lport, channel_info_ss[i]->rport);
    }
    vtun_syslog(LOG_INFO, "fss conn_counter is %i", conn_counter);
#endif
}

/**
 * Parse netlink message to channel_info structure
 *
 * @param nlh
 * @param r
 * @return 0 - error and 1 as success
 */
int format_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r) {

    struct rtattr * tb[INET_DIAG_MAX + 1];
    struct tcp_info *info;

    parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr*) (r + 1), nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

    if (tb[INET_DIAG_INFO]) {
        int len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

        /* workaround for older kernels with less fields ???legacy??? */
        if (len < sizeof(*info)) {
            info = alloca(sizeof(*info));
            memset(info, 0, sizeof(*info));
            memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
        } else {
            info = RTA_DATA(tb[INET_DIAG_INFO]);
        }
    } else {
        return 0;
    }
    if (info == 0) {
        return 0;
    }

    memset(channel_info_ss[conn_counter], 0, sizeof(channel_info_ss));
    channel_info_ss[conn_counter]->snd_wscale = info->tcpi_snd_wscale;
    channel_info_ss[conn_counter]->rcv_wscale = info->tcpi_rcv_wscale;
    if (info->tcpi_rto && info->tcpi_rto != 3000000) {
        channel_info_ss[conn_counter]->rto = (double) info->tcpi_rto / 1000;
    }
    channel_info_ss[conn_counter]->rtt = (double) info->tcpi_rtt / 1000;
    channel_info_ss[conn_counter]->rtt_var = (double) info->tcpi_rttvar / 1000;
    channel_info_ss[conn_counter]->ato = (double) info->tcpi_ato / 1000;
    if (info->tcpi_snd_cwnd != 2) { // really need?
        channel_info_ss[conn_counter]->cwnd = info->tcpi_snd_cwnd;
    }
    if (info->tcpi_snd_ssthresh < 0xFFFF) {
        channel_info_ss[conn_counter]->ssthresh = info->tcpi_snd_ssthresh;
    }
    if (channel_info_ss[conn_counter]->rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
        channel_info_ss[conn_counter]->send = (uint32_t) ((double) info->tcpi_snd_cwnd * (double) info->tcpi_snd_mss * 1000. / channel_info_ss[conn_counter]->rtt);
    }
    channel_info_ss[conn_counter]->mss = info->tcpi_snd_mss;
    channel_info_ss[conn_counter]->rcv_rtt = (double) info->tcpi_rcv_rtt / 1000;
    channel_info_ss[conn_counter]->rcv_space = info->tcpi_rcv_space;
    return 1;
}
