/*	$KAME: addrconf.c,v 1.8 2005/09/16 11:30:13 suz Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif

#include <netinet/in.h>

#ifdef __KAME__
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#endif

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "dhcp6c_ia.h"
#include "prefixconf.h"

TAILQ_HEAD(statefuladdr_list, statefuladdr);
struct iactl_na {
	struct iactl common;
	struct statefuladdr_list statefuladdr_head;
};
#define iacna_ia common.iactl_ia
#define iacna_callback common.callback
#define iacna_isvalid common.isvalid
#define iacna_duration common.duration
#define iacna_renew_data common.renew_data
#define iacna_rebind_data common.rebind_data
#define iacna_reestablish_data common.reestablish_data
#define iacna_release_data common.release_data
#define iacna_cleanup common.cleanup

struct statefuladdr {
	TAILQ_ENTRY (statefuladdr) link;

	struct dhcp6_statefuladdr addr;
	time_t updatetime;
	struct dhcp6_timer *timer;
	struct iactl_na *ctl;
	struct dhcp6_if *dhcpif;
};

static struct statefuladdr *find_addr __P((struct statefuladdr_list *,
    struct dhcp6_statefuladdr *));
static int remove_addr __P((struct statefuladdr *));
static int isvalid_addr __P((struct iactl *));
static u_int32_t duration_addr __P((struct iactl *));
static void cleanup_addr __P((struct iactl *));
static int renew_addr __P((struct iactl *, struct dhcp6_ia *,
    struct dhcp6_eventdata **, struct dhcp6_eventdata *));
static void na_renew_data_free __P((struct dhcp6_eventdata *));

static struct dhcp6_timer *addr_timo __P((void *));

static int na_ifaddrconf __P((ifaddrconf_cmd_t, struct statefuladdr *));

extern struct dhcp6_timer *client6_timo __P((void *));

/* =================================================================== */

#if 1
extern int decline_ia __P((struct ia *ia));
#include <fcntl.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NS_INADDRSZ     4       /* IPv4 T_A */
#define NS_IN6ADDRSZ    16      /* IPv6 T_AAAA */
#define NS_INT16SZ      2       /* #/bytes of data in a u_int16_t */
#define u_char unsigned char
#define u_int  unsigned int

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
};

struct idxmap
{
	struct idxmap * next;
	unsigned	index;
	int		type;
	int		alen;
	unsigned	flags;
	unsigned char	addr[8];
	char		name[16];
};

struct _nlmsg_list
{
	struct _nlmsg_list *next;
	struct nlmsghdr	  h;
};

typedef int (*rtnl_filter_t)(const struct sockaddr_nl *, 
			     struct nlmsghdr *n, void *);

static struct idxmap *idxmap[16];

static int inet_pton4(const char * src, char * dst)
{
	int saw_digit, octets, ch;
	u_char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {

		if (ch >= '0' && ch <= '9') {
			u_int new = *tp * 10 + (ch - '0');

			if (new > 255)
				return (0);
			*tp = new;
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

int inet_pton6(const char *src, char * dst)
{
	static char xdigits[] = "0123456789abcdef";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset(tmp, '\0', NS_IN6ADDRSZ);
	tp = tmp;
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = tolower (*src++)) != '\0') {
		char * pch;

		pch = strchr(xdigits, ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
		    inet_pton4(curtok, (char*)tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}


char * inet_ntop6(const char * src2, char * dst)
{
    const unsigned char* src = (unsigned char*)src2;

	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;
	best.len = cur.len = 0;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i += 2)
		words[i / 2] = (src[i] << 8) | src[i + 1];
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
#if 0
		/* encapsulated IPv4 addresses are no concern in Dibbler */
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4((char*)src+12, tp))
				return (NULL);
			tp += strlen(tp);
			break;
		}
#endif
		tp += sprintf(tp, "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';
	return strcpy(dst, tmp);
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int rcvbuf = 32768;

	memset(rth, 0, sizeof(struct rtnl_handle));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}


int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;

	return sendto(rth->fd, (void*)&req, sizeof(req), 0,
		      (struct sockaddr*)&nladdr, sizeof(nladdr));
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int ll_remember_index(const struct sockaddr_nl *who, 
		      struct nlmsghdr *n, void *arg)
{
	int h;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct idxmap *im, **imp;
	struct rtattr *tb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
		return -1;


	memset(tb, 0, sizeof(*tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
	if (tb[IFLA_IFNAME] == NULL)
		return 0;

	h = ifi->ifi_index&0xF;

	for (imp=&idxmap[h]; (im=*imp)!=NULL; imp = &im->next)
		if (im->index == ifi->ifi_index)
			break;

	if (im == NULL) {
		im = malloc(sizeof(*im));
		if (im == NULL)
			return 0;
		im->next = *imp;
		im->index = ifi->ifi_index;
		*imp = im;
	}

	im->type = ifi->ifi_type;
	im->flags = ifi->ifi_flags;
	if (tb[IFLA_ADDRESS]) {
		int alen;
		im->alen = alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
		if (alen > sizeof(im->addr))
			alen = sizeof(im->addr);
		memcpy(im->addr, RTA_DATA(tb[IFLA_ADDRESS]), alen);
	} else {
		im->alen = 0;
		memset(im->addr, 0, sizeof(im->addr));
	}
	strcpy(im->name, RTA_DATA(tb[IFLA_IFNAME]));
	return 0;
}

int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
    struct _nlmsg_list **linfo = (struct _nlmsg_list**)arg;
    struct _nlmsg_list *h;
    struct _nlmsg_list **lp;
    
    h = malloc(n->nlmsg_len+sizeof(void*));
    if (h == NULL)
	return -1;
    
    memcpy(&h->h, n, n->nlmsg_len);
    h->next = NULL;
    
    for (lp = linfo; *lp; lp = &(*lp)->next) /* NOTHING */;
    *lp = h;
    
    ll_remember_index(who, n, NULL);
    return 0;
}

int rtnl_dump_filter(struct rtnl_handle *rth,
		     rtnl_filter_t filter,
		     void *arg1,
		     rtnl_filter_t junk,
		     void *arg2)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];

	iov.iov_base = buf;
	while (1) {
		int status;
		struct nlmsghdr *h;

		iov.iov_len = sizeof(buf);
		status = recvmsg(rth->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			perror("OVERRUN");
			continue;
		}

		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}

		h = (struct nlmsghdr*)buf;
		while (NLMSG_OK(h, status)) {
			int err;

			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid != rth->local.nl_pid ||
			    h->nlmsg_seq != rth->dump) {
				if (junk) {
					err = junk(&nladdr, h, arg2);
					if (err < 0)
						return err;
				}
				goto skip_it;
			}

			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
					fprintf(stderr, "ERROR truncated\n");
				} else {
					errno = -err->error;
					perror("RTNETLINK answers");
				}
				return -1;
			}
			err = filter(&nladdr, h, arg1);
			if (err < 0)
				return err;

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
}


void rtnl_close(struct rtnl_handle *rth)
{
	close(rth->fd);
}

/*
 * returns: -1 - address not found, 0 - addr is ok, 1 - addr is tentative
 */
int is_addr_tentative(char * ifacename, char * addr)
{
    char buf[256];
    char packed1[16];
    char packed2[16];
    struct rtattr * rta_tb[IFA_MAX+1];
    struct _nlmsg_list *ainfo = NULL;
    struct _nlmsg_list *head = NULL;
    struct rtnl_handle rth;
    int iface;

    int tentative = -1;

    if (ifacename != NULL) {
		iface = if_nametoindex(ifacename);
		IPV6_ECHO("iface: %d\n", iface);
    	if (iface == 0) {
    		return -1;
    	}
    }

    inet_pton6(addr,packed1);

    rtnl_open(&rth, 0);

    /* 2nd attribute: AF_UNSPEC, AF_INET, AF_INET6 */
    /* rtnl_wilddump_request(&rth, AF_PACKET, RTM_GETLINK); */
    rtnl_wilddump_request(&rth, AF_INET6, RTM_GETADDR);
    rtnl_dump_filter(&rth, store_nlmsg, &ainfo, NULL, NULL);

    head = ainfo;
    while (ainfo) {
		struct nlmsghdr *n = &ainfo->h;
		struct ifaddrmsg *ifa = NLMSG_DATA(n);
		
		memset(rta_tb, 0, sizeof(*rta_tb));

		IPV6_ECHO("ifa->ifa_index: %d\n", ifa->ifa_index);
		if (ifa->ifa_index == iface && ifa->ifa_family==AF_INET6) {
		    parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa), n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
		    if (!rta_tb[IFA_LOCAL])   
				rta_tb[IFA_LOCAL]   = rta_tb[IFA_ADDRESS];
		    if (!rta_tb[IFA_ADDRESS]) 
				rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];
		    
		    inet_ntop6(RTA_DATA(rta_tb[IFA_LOCAL]), buf /*, sizeof(buf)*/);
		    memcpy(packed2,RTA_DATA(rta_tb[IFA_LOCAL]),16);

		    /* print_packed(packed1); printf(" "); print_packed(packed2); printf("\n"); */

		    /* is this addr which are we looking for? */
		    if (!memcmp(packed1,packed2,16) ) {
				if (ifa->ifa_flags & IFA_F_TENTATIVE)
				    tentative = 1;
				else
				    tentative = 0;
		    }
		}
		ainfo = ainfo->next;
    }

    /* now delete list */
    while (head) {
		ainfo = head;
		head = head->next;
		free(ainfo);
    }
    
    rtnl_close(&rth);

    return tentative;
}

static int _read2buf(const char *path, void *buf, int len)
{
	int fd;
	char *str = (char *)buf;
	int ret = 0;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	ret = read(fd, buf, len);
	(void)close(fd);

	while (ret > 0) {
		switch (str[ret -1]) {
		case ' ':
		case '\t':
		case '\n':
			str[ret - 1] = '\0';
			break;
		default:
			break;
		}

		/* printf("%s\n", str[ret - 1] == '\0' ? "true" : "false"); */
		if (str[ret - 1] == '\0') {
			ret -= 1;
		} else {
			break;
		}
	}

	return ret;
}

static int is_dad_accept(ifname)
	const char *ifname;
{
	int dad_accept = 0;
	char path[256] = {0};
	char buf[128] = {0};

	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/accept_dad", ifname);
	_read2buf(path, buf, sizeof(buf));
	dad_accept = atoi(buf);
	return dad_accept;
}

static int get_dad_trans_time(ifname)
	const char *ifname;
{
	int dad_trans_time = -1;
	char path[256] = {0};
	char buf[128] = {0};

	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/dad_transmits", ifname);
	_read2buf(path, buf, sizeof(buf));
	dad_trans_time = atoi(buf);
	
	return dad_trans_time;
}
#endif
/* =================================================================== */


int
update_address(ia, addr, dhcpifp, ctlp, callback)
	struct ia *ia;
	struct dhcp6_statefuladdr *addr;
	struct dhcp6_if *dhcpifp;
	struct iactl **ctlp;
	void (*callback)__P((struct ia *));
{
	struct iactl_na *iac_na = (struct iactl_na *)*ctlp;
	struct statefuladdr *sa;
	int sacreate = 0;
	struct timeval timo;

	/*
	 * A client discards any addresses for which the preferred
         * lifetime is greater than the valid lifetime.
	 * [RFC3315 22.6] 
	 */
	if (addr->vltime != DHCP6_DURATION_INFINITE &&
	    (addr->pltime == DHCP6_DURATION_INFINITE ||
	    addr->pltime > addr->vltime)) {
		debug_printf(LOG_INFO, FNAME, "invalid address %s: "
		    "pltime (%lu) is larger than vltime (%lu)",
		    in6addr2str(&addr->addr, 0),
		    addr->pltime, addr->vltime);
		return (-1);
	}

	if (iac_na == NULL) {
		if ((iac_na = malloc(sizeof(*iac_na))) == NULL) {
			debug_printf(LOG_NOTICE, FNAME, "memory allocation failed");
			return (-1);
		}
		memset(iac_na, 0, sizeof(*iac_na));
		iac_na->iacna_ia = ia;
		iac_na->iacna_callback = callback;
		iac_na->iacna_isvalid = isvalid_addr;
		iac_na->iacna_duration = duration_addr;
		iac_na->iacna_cleanup = cleanup_addr;
		iac_na->iacna_renew_data =
		    iac_na->iacna_rebind_data =
		    iac_na->iacna_release_data =
		    iac_na->iacna_reestablish_data = renew_addr;

		TAILQ_INIT(&iac_na->statefuladdr_head);
		*ctlp = (struct iactl *)iac_na;
	}

	/* search for the given address, and make a new one if it fails */
	if ((sa = find_addr(&iac_na->statefuladdr_head, addr)) == NULL) {
		if ((sa = malloc(sizeof(*sa))) == NULL) {
			debug_printf(LOG_NOTICE, FNAME, "memory allocation failed");
			return (-1);
		}
		memset(sa, 0, sizeof(*sa));
		sa->addr.addr = addr->addr;
		sa->ctl = iac_na;
		TAILQ_INSERT_TAIL(&iac_na->statefuladdr_head, sa, link);
		sacreate = 1;
	}

	/* update the timestamp of update */
	sa->updatetime = time(NULL);

	/* update the prefix according to addr */
	sa->addr.pltime = addr->pltime;
	sa->addr.vltime = addr->vltime;
	sa->dhcpif = dhcpifp;
	debug_printf(LOG_DEBUG, FNAME, "%s an address %s pltime=%lu, vltime=%lu",
	    sacreate ? "create" : "update",
	    in6addr2str(&addr->addr, 0), addr->pltime, addr->vltime);
	IPV6_ECHO("%s an address %s pltime=%lu, vltime=%lu",
	    sacreate ? "create" : "update",
	    in6addr2str(&addr->addr, 0), addr->pltime, addr->vltime);
	if (sa->addr.vltime != 0) {
		if (na_ifaddrconf(IFADDRCONF_ADD, sa) < 0) {
			return (-1);
		} 
		else {					
			if (is_dad_accept(dhcpifp->ifname)) {
				int ret;
				int sleep_time = get_dad_trans_time(dhcpifp->ifname) + 1;
				sleep(sleep_time);
				ret = is_addr_tentative(dhcpifp->ifname, in6addr2str(&addr->addr, 0));
				IPV6_ECHO("tentative: %d\n", ret);
				
				if (ret == 1) {
					/* send decline */
					decline_ia(ia);
					remove_addr(sa);
					ia->state = IAS_DECLINE;
					return (-1);
				}
			}
		}
	}
	/*
	 * If the new vltime is 0, this address immediately expires.
	 * Otherwise, set up or update the associated timer.
	 */
	switch (sa->addr.vltime) {
	case 0:
		if (remove_addr(sa) < 0)
			return (-1);
		break;
	case DHCP6_DURATION_INFINITE:
		if (sa->timer)
			dhcp6_remove_timer(&sa->timer);
		break;
	default:
		if (sa->timer == NULL) {
			sa->timer = dhcp6_add_timer(addr_timo, sa);
			if (sa->timer == NULL) {
				debug_printf(LOG_NOTICE, FNAME,
				    "failed to add stateful addr timer");
				remove_addr(sa); /* XXX */
				return (-1);
			}
		}
		/* update the timer */
		timo.tv_sec = sa->addr.vltime;
		timo.tv_usec = 0;

		dhcp6_set_timer(&timo, sa->timer);
		break;
	}

	return (0);
}

static struct statefuladdr *
find_addr(head, addr)
	struct statefuladdr_list *head;
	struct dhcp6_statefuladdr *addr;
{
	struct statefuladdr *sa;

	for (sa = TAILQ_FIRST(head); sa; sa = TAILQ_NEXT(sa, link)) {
		if (!IN6_ARE_ADDR_EQUAL(&sa->addr.addr, &addr->addr))
			continue;
		return (sa);
	}

	return (NULL);
}

static int
remove_addr(sa)
	struct statefuladdr *sa;
{
	int ret;

	debug_printf(LOG_DEBUG, FNAME, "remove an address %s",
	    in6addr2str(&sa->addr.addr, 0));

	if (sa->timer)
		dhcp6_remove_timer(&sa->timer);

	TAILQ_REMOVE(&sa->ctl->statefuladdr_head, sa, link);
	ret = na_ifaddrconf(IFADDRCONF_REMOVE, sa);
	free(sa);

	return (ret);
}

static int
isvalid_addr(iac)
	struct iactl *iac;
{
	struct iactl_na *iac_na = (struct iactl_na *)iac;

	if (TAILQ_EMPTY(&iac_na->statefuladdr_head))
		return (0);	/* this IA is invalid */
	return (1);
}

static u_int32_t
duration_addr(iac)
	struct iactl *iac;
{
	struct iactl_na *iac_na = (struct iactl_na *)iac;
	struct statefuladdr *sa;
	u_int32_t base = DHCP6_DURATION_INFINITE, pltime, passed;
	time_t now;

	/* Determine the smallest period until pltime expires. */
	now = time(NULL);
	for (sa = TAILQ_FIRST(&iac_na->statefuladdr_head); sa;
	    sa = TAILQ_NEXT(sa, link)) {
		passed = now > sa->updatetime ?
		    (u_int32_t)(now - sa->updatetime) : 0;
		pltime = sa->addr.pltime > passed ?
		    sa->addr.pltime - passed : 0;

		if (base == DHCP6_DURATION_INFINITE || pltime < base)
			base = pltime;
	}

	return (base);
}

static void
cleanup_addr(iac)
	struct iactl *iac;
{
	struct iactl_na *iac_na = (struct iactl_na *)iac;
	struct statefuladdr *sa;

	while ((sa = TAILQ_FIRST(&iac_na->statefuladdr_head)) != NULL) {
		TAILQ_REMOVE(&iac_na->statefuladdr_head, sa, link);
		remove_addr(sa);
	}

	free(iac);
}

static int
renew_addr(iac, iaparam, evdp, evd)
	struct iactl *iac;
	struct dhcp6_ia *iaparam;
	struct dhcp6_eventdata **evdp, *evd;
{
	struct iactl_na *iac_na = (struct iactl_na *)iac;
	struct statefuladdr *sa;
	struct dhcp6_list *ial = NULL, pl;

	TAILQ_INIT(&pl);
	for (sa = TAILQ_FIRST(&iac_na->statefuladdr_head); sa;
	    sa = TAILQ_NEXT(sa, link)) {
		if (dhcp6_add_listval(&pl, DHCP6_LISTVAL_STATEFULADDR6,
		    &sa->addr, NULL) == NULL)
			goto fail;
	}

	if ((ial = malloc(sizeof(*ial))) == NULL)
		goto fail;
	TAILQ_INIT(ial);
	if (dhcp6_add_listval(ial, DHCP6_LISTVAL_IANA, iaparam, &pl) == NULL)
		goto fail;
	dhcp6_clear_list(&pl);

	evd->type = DHCP6_EVDATA_IANA;
	evd->data = (void *)ial;
	evd->privdata = (void *)evdp;
	evd->destructor = na_renew_data_free;

	return (0);

  fail:
	dhcp6_clear_list(&pl);
	if (ial)
		free(ial);
	return (-1);
}

static void
na_renew_data_free(evd)
	struct dhcp6_eventdata *evd;
{
	struct dhcp6_list *ial;

	if (evd->type != DHCP6_EVDATA_IANA) {
		debug_printf(LOG_ERR, FNAME, "assumption failure");
		exit(1);
	}

	if (evd->privdata)
		*(struct dhcp6_eventdata **)evd->privdata = NULL;
	ial = (struct dhcp6_list *)evd->data;
	dhcp6_clear_list(ial);
	free(ial);
}

static struct dhcp6_timer *
addr_timo(arg)
	void *arg;
{
	struct statefuladdr *sa = (struct statefuladdr *)arg;
	struct ia *ia;
	void (*callback)__P((struct ia *));

	debug_printf(LOG_DEBUG, FNAME, "address timeout for %s",
	    in6addr2str(&sa->addr.addr, 0));

	ia = sa->ctl->iacna_ia;
	callback = sa->ctl->iacna_callback;

	if (sa->timer)
		dhcp6_remove_timer(&sa->timer);

	remove_addr(sa);

	(*callback)(ia);

	return (NULL);
}

static int
na_ifaddrconf(cmd, sa)
	ifaddrconf_cmd_t cmd;
	struct statefuladdr *sa;
{
	struct dhcp6_statefuladdr *addr;
	struct sockaddr_in6 sin6;

	addr = &sa->addr;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif
	sin6.sin6_addr = addr->addr;

#if 0 /* changed by ZQQ, set the prefix length = 64, 14Apr2011 */
	return (ifaddrconf(cmd, sa->dhcpif->ifname, &sin6, 128,
	    addr->pltime, addr->vltime));
#endif 
	printf("%s %d: ifaddrconf: cmd = %d,sa->dhcpif->ifname = %s, addr->pltime = %d, addr->vltime= %d\r\n" ,__FUNCTION__, __LINE__, cmd, sa->dhcpif->ifname,addr->pltime, addr->vltime);
	return (ifaddrconf(cmd, sa->dhcpif->ifname, &sin6, 64, 
	    addr->pltime, addr->vltime));

}
