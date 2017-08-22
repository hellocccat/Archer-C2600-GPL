/*! Copyright(c) 2008-2014 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     connect.c
 *\brief        
 *\details  
 *
 *\author   Zhu Xianfeng<zhuxianfeng@tp-link.net>
 *\version  1.0.0
 *\date     29May14
 *
 *\warning  
 *
 *\history \arg 29May14, Zhu Xianfeng, create the file.
 */
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "system.h"
#include "connect.h"

#define IPT_STAT_BASE_CTL         (128)
#define IPT_STAT_SET_NET          (IPT_STAT_BASE_CTL)
#define IPT_STAT_DEL_ALL          (IPT_STAT_BASE_CTL + 5)
#define IPT_STAT_GET_WAN_STAT     (IPT_STAT_BASE_CTL + 1)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)             (sizeof(x)/sizeof(x[0]))
#endif
#define CONNECT_IFACE_WAN         "wan"
#define CONNECT_IFACE_WANV6       "wanv6"
#define CONNECT_IFACE_LAN         "lan"
#define CONNECT_IFACE_INTERNET    "internet"
#define CONNECT_IFACE_INTERNETV6  "internetv6"
#define CONNECT_IFNAME_LAN        "br-lan"
#define CONNECT_MACADDR_LEN       (6)
#define CONNECT_TIMEOUT           (1000)
#define dprintf(fmt, args...)     D(CONNCTL, fmt, ##args)

enum iface_proto
{
	IFP_INVALID,
	IFP_STATIC,
	IFP_DHCP,
	IFP_DHCPV6,
	IFP_PPPOE,
	IFP_PPPOEV6,
	IFP_L2TP,
	IFP_PPTP,
	IFP_BIGPOND,
	IFP_6TO4,
	IFP_6RD,
	IFP_DSLITE,
	IFP_PASSTHROUGH,
};

struct ipt_net
{
	uint32_t ip;
	uint32_t mask;
};

struct ipt_stat
{
	uint64_t rcv_pkt;
	uint64_t rcv_byte;
	uint64_t snd_pkt;
	uint64_t snd_byte;
};

struct conn_handler
{
	enum interface_conn_mode mode;
	void (*process)(struct interface *iface);
};

static int connect_ipt_outgone();
static void connect_auto(struct interface *iface);
static void connect_manual(struct interface *iface);
static void connect_demand(struct interface *iface);
static void connect_timebased(struct interface *iface);
static void connect_dft_route(int add);

static int initialized;
static int tmp_ip_set;
static char tmp_ip_str[16];
static struct ipt_stat last_stat;
static struct uloop_timeout timeout;
static struct conn_handler conn_handlers[] =
{
	{
		.mode = IFCM_AUTO,
		.process = connect_auto,
	},
	{
		.mode = IFCM_MANUAL,
		.process = connect_manual,
	},
	{
		.mode = IFCM_DEMAND,
		.process = connect_demand,
	},
	{
		.mode = IFCM_TIMEBASED,
		.process = connect_timebased,
	},
};
static char *valid_ifaces[] =
{
	CONNECT_IFACE_WAN,
	CONNECT_IFACE_WANV6,
	CONNECT_IFACE_INTERNET,
	CONNECT_IFACE_INTERNETV6,
	NULL,
};

static void
connect_ifup(struct interface *iface)
{
	struct interface *parent = NULL;

	if (strcmp(iface->name, CONNECT_IFACE_INTERNET) == 0)
	{
		parent = vlist_find(&interfaces, CONNECT_IFACE_WAN, iface, node);
	}
	else if (strcmp(iface->name, CONNECT_IFACE_INTERNETV6) == 0)
	{
		parent = vlist_find(&interfaces, CONNECT_IFACE_WANV6, iface, node);
	}
	else if (strcmp(iface->name, CONNECT_IFACE_WAN) == 0)
	{
		/* If connect down the WAN_VIF, the VIF device will be removed. */
		/* While connect up the WAN_VIF, The VIF device should be added again. */
		/* Added by xlw, 2015-04-15 */
		struct device_user *main_dev = &iface->main_dev;
		if(main_dev){
			struct device *dev = main_dev->dev;
			if(dev){
				dev->set_state(dev, true);
			}
		}
	}

	if (parent && parent->state == IFS_DOWN)
	{
#if 0
		dprintf("interface(%p): %s, available: %d, connectable: %d, state: %d, conn_mode: %d\n",
			    iface, iface->name, iface->available, 
				iface->connectable, iface->state, iface->conn_mode);
#endif
		(void)interface_set_up(parent);
	}

	if (iface->state == IFS_DOWN) 
	{
		dprintf("interface(%s) set up\n", iface->name);
		(void)interface_set_up(iface);
	}
}

static void
connect_ifdown(struct interface *iface)
{
	struct interface *parent = NULL;
	bool pppoe = false;

	if (strcmp(iface->name, CONNECT_IFACE_INTERNET) == 0)
	{
		parent = vlist_find(&interfaces, CONNECT_IFACE_WAN, iface, node);
	}
	else if (strcmp(iface->name, CONNECT_IFACE_INTERNETV6) == 0)
	{
		parent = vlist_find(&interfaces, CONNECT_IFACE_WANV6, iface, node);
	}

	/* Sequential action: 
	 *   1. Down L2TP/PPTP/PPPoE;
	 *   2. Down DHCP;
	 * Make sure both PPP Termination and DHCP Release frame was transmitted.
	 */

	if (iface->state != IFS_DOWN)
	{
		dprintf("interface_set_down %s\n", iface->name);
		(void)interface_set_down(iface);
	}

	if (iface->proto_handler && strcmp(iface->proto_handler->name, "pppoe") == 0)
	{
		pppoe = true;
	}

	if (iface->state == IFS_DOWN && parent && !pppoe)
	{
        if (parent->state != IFS_DOWN)
        {
            dprintf("interface_set_down %s\n", parent->name);
            (void)interface_set_down(parent);
        }
	}
}

static bool 
connect_ifvalid(struct interface *iface)
{
	char **ptr;

	for (ptr = valid_ifaces; *ptr != NULL; ptr++)
	{
		if (strcmp(iface->name, *ptr) == 0)
		{
			return true;
		}
	}

	return false;
}

/* Return iface's proto */
static enum iface_proto
connect_ifproto(struct interface *iface)
{
	const struct proto_handler *handler = iface->proto_handler;

	if (handler)
	{
		if (strcmp(handler->name, "static") == 0)
		{
			return IFP_STATIC;
		}
		else if (strcmp(handler->name, "dhcp") == 0)
		{
			return IFP_DHCP;
		}
		else if (strcmp(handler->name, "pppoe") == 0)
		{
			return IFP_PPPOE;
		}
		else if (strcmp(handler->name, "l2tp") == 0)
		{
			return IFP_L2TP;
		}
		else if (strcmp(handler->name, "pptp") == 0)
		{
			return IFP_PPTP;
		}
		else if (strcmp(handler->name, "bigpond") == 0)
		{
			return IFP_BIGPOND;
		}
	}

	return IFP_INVALID;
}

static void 
connect_auto(struct interface *iface)
{
	struct interface *internet = NULL;
	struct interface *internetv6 = NULL;
	bool dhcp = false;
	bool dhcpv6 = false;
	unsigned int flags = 0;
	int ret = 0;

	internet = vlist_find(&interfaces, CONNECT_IFACE_INTERNET, internet, node);
	if (!internet && strcmp(iface->name, CONNECT_IFACE_WAN) == 0 &&
		iface->proto_handler && strcmp(iface->proto_handler->name, "dhcp") == 0)
	{
		dhcp = true;
	}

	internetv6 = vlist_find(&interfaces, CONNECT_IFACE_INTERNETV6, internetv6, node);
	if (!internetv6 && strcmp(iface->name, CONNECT_IFACE_WANV6) == 0 &&
		iface->proto_handler && strcmp(iface->proto_handler->name, "dhcp6c") == 0)
	{
		dhcpv6 = true;
	}
	
	/* device unplugged handler for DHCP */
	if (dhcp || dhcpv6)
	{
		if (iface->ifname)
		{
			ret = system_if_get_flags(iface->ifname, &flags);
			if (!ret)
			{
				iface->link_state = !!(flags & IFF_RUNNING);
			}
		}

		if (!iface->link_state)
		{
			if (iface->state == IFS_UP)
			{
				(void)interface_set_down(iface);
			}

			/* link down handled completely */
			return;
		}
	}

	if (iface->state != IFS_UP) 
	{
		connect_ifup(iface);
	}
}

static void 
connect_manual(struct interface *iface)
{
	time_t now = 0;
	int valid = 0;
	int ret = 0;

	dprintf("interface: %s, state: %d, idle: %ld\n", 
		iface->name, iface->state, iface->conn_time.idle);

	if (iface->conn_time.idle == 0)
	{
		return;
	}

	ret = connect_ipt_outgone();
	dprintf("lan -> wan had outgoing pkts: %s\n", ret ? "yes" : "no");
	now = time(NULL);
	if (!iface->conn_time.last)
	{
		iface->conn_time.last = now;
	}
	if (ret)
	{
		/* lan -> wan had outgoing pkts */
		iface->conn_time.last = now;
		valid = 1;
	}
	else if ((now - iface->conn_time.last) >= iface->conn_time.idle)
	{
		dprintf("connectable timeout\n");
		valid = 0;
	}
	else
	{
		valid = 1;
	}

	if (!valid)
	{
		connect_ifdown(iface);
	}

	return; 
}

/* Demand connection: PPPoE/L2TP/PPTP */
static void 
connect_demand(struct interface *iface)
{
	struct interface *parent = NULL;
	enum iface_proto proto;
	time_t now;
	int valid = 0;
	int ret = 0;

	dprintf("interface: %s, state: %d, idle: %ld\n", 
		iface->name, iface->state, iface->conn_time.idle);

	proto = connect_ifproto(iface);

	if (strcmp(iface->name, CONNECT_IFACE_INTERNET) == 0)
	{
		parent = vlist_find(&interfaces, CONNECT_IFACE_WAN, iface, node);
	}

	ret = connect_ipt_outgone();
	dprintf("lan -> wan had outgoing pkts: %s\n", ret ? "yes" : "no");
	now = time(NULL);
	if (ret)
	{
		/* lan -> wan had outgoing pkts */
		iface->conn_time.last = now;
		valid = 1;
	}
	else if (!iface->conn_time.idle)
	{
		dprintf("ignore connect handle\n");
		valid = -1;
	}
	else if ((now - iface->conn_time.last) >= iface->conn_time.idle)
	{
		dprintf("connectable timeout\n");
		valid = 0;
	}
	else
	{
		dprintf("connectable valid\n");
		valid = 1;
	}

	if (valid > 0)
	{
		connect_ifup(iface);
	}
	else if (valid < 0)
	{
		/* ignore */
	}
	else 
	{
		connect_ifdown(iface);
	}

    if (iface->state == IFS_DOWN && proto == IFP_PPPOE)
    {
        connect_dft_route(1);
    }
    else if (iface->state == IFS_DOWN && !parent)
    {
        connect_dft_route(1);
    }
    else if (iface->state == IFS_DOWN && parent && parent->state == IFS_DOWN)
    {
        connect_dft_route(1);
    }
    else
    {
        connect_dft_route(0);
    }

	return;
}

/* Time based connection: PPPoE */
static void 
connect_timebased(struct interface *iface)
{
	struct tm cur;
	time_t cur_sec;
	int valid = 0;
	int ret = 0;

	ret = system_get_localtime(&cur);
	if (ret != 0)
	{
		return;
	}

	cur_sec = cur.tm_hour * 60 * 60 + cur.tm_min * 60 + cur.tm_sec;
	if (cur_sec > iface->conn_time.start && cur_sec < iface->conn_time.end)
	{
		valid = 1;
	}

	if (valid)
	{
		connect_ifup(iface);
	}
	else
	{
		connect_ifdown(iface);
	}
}

static int 
connect_process()
{
	struct interface *iface;
	struct interface *internet = NULL;
	int i = 0;

	internet = vlist_find(&interfaces, CONNECT_IFACE_INTERNET, internet, node);
	if (internet != NULL && internet->conn_mode != IFCM_DEMAND)
	{
		connect_dft_route(0);
	}

	vlist_for_each_element(&interfaces, iface, node) 
	{
		if (!connect_ifvalid(iface))
		{
			continue;
		}

		/* dprintf("interface(%p): %s, available: %d, connectable: %d, state: %d, conn_mode: %d\n",
			    iface, iface->name, iface->available, 
				iface->connectable, iface->state, iface->conn_mode); */

		if (!iface->connectable)
		{
			connect_ifdown(iface);
			continue;
		}

		for (i = 0; i < ARRAY_SIZE(conn_handlers); i++)
		{
			if (iface->conn_mode == conn_handlers[i].mode)
			{
				conn_handlers[i].process(iface);
				break;
			}

			/* Invalid connect mode, ignore */
		}
	}

	return 0;
}

static void 
connect_timeout(struct uloop_timeout *timeout)
{
	(void)connect_process();
	(void)uloop_timeout_set(timeout, CONNECT_TIMEOUT);
}

#if 0
static int
connect_dev_hasip(const char *ifname)
{
	uint32_t ip = 0;
	int ret = 0;

	ret = system_if_get_addr(ifname, &ip);
	if (ret != 0 || ip == 0)
	{
		return 0;
	}

	return 1;
}
#endif

static void
connect_dft_route(int add)
{
	const char *dftgw = "1.0.0.1";
	const char *wan_ifname;
	const char *lan_ifname;
	const char *lan_ipaddr;
	uint8_t macaddr[CONNECT_MACADDR_LEN];
	int ret = 0;

	wan_ifname = config_option_str(CONNECT_IFACE_WAN, "ifname");
	if (!wan_ifname) 
	{
		dprintf("interface %s: invalid option ifname\n", CONNECT_IFACE_WAN);
		return;
	}

	if (add)
	{
#if 0
		if (tmp_ip_set || connect_dev_hasip(wan_ifname))
		{
			/* tmp ip addr for wan's device is set already, or it has ip */
			return;
		}
#endif

		lan_ifname = config_option_str(CONNECT_IFACE_LAN, "ifname");
		if (!lan_ifname)
		{
			dprintf("interface %s: invalid option ifname\n", CONNECT_IFACE_LAN);
			return;
		}

		lan_ipaddr = config_option_str(CONNECT_IFACE_LAN, "ipaddr");
		if (!lan_ipaddr)
		{
			dprintf("interface %s: invalid option ipaddr\n", CONNECT_IFNAME_LAN);
			return;
		}

		ret = system_if_get_macaddr(lan_ifname, macaddr);
		if (ret != 0)
		{
			dprintf("ifname %s: can't get macaddr\n", lan_ifname);
			return;
		}

		/* system_exec_fmt("ifconfig %s 0.0.0.0", wan_ifname); */
		memset(tmp_ip_str, 0, sizeof(tmp_ip_str));
		if ((macaddr[CONNECT_MACADDR_LEN - 1] != 0x01) &&
			(macaddr[CONNECT_MACADDR_LEN - 1] != 0xFF))
		{
			snprintf(tmp_ip_str, sizeof(tmp_ip_str), "1.0.%d.%d", 
				macaddr[CONNECT_MACADDR_LEN - 2], 
				macaddr[CONNECT_MACADDR_LEN - 1]);
		}
		else
		{
			snprintf(tmp_ip_str, sizeof(tmp_ip_str), "1.0.%d.10", 
				macaddr[CONNECT_MACADDR_LEN - 2]);
		}

		/* system_exec_fmt("ifconfig %s %s", wan_ifname, tmp_ip_str); */
		system_exec_fmt("ip addr add %s/8 dev eth0", tmp_ip_str, wan_ifname);
		system_exec_fmt("ip route replace default via %s dev %s", dftgw, wan_ifname);
		system_exec_fmt("ifconfig %s up", wan_ifname);
		system_exec_fmt("nat del dns && nat add dns { %s %s }", lan_ipaddr, dftgw);
		tmp_ip_set = 1;
	}
	else 
	{
		if (tmp_ip_set)
		{
			/* delete tmp ip and default route */
			system_exec_fmt("ip addr del %s/8 dev %s", tmp_ip_str, wan_ifname);
			/* dnsproxy will execute nat del dns */
			/* system_exec_cmd("nat del dns"); */
			tmp_ip_set = 0;
		}
	}
}

static int 
connect_ipt_stat(struct ipt_stat *stat)
{
	socklen_t len = sizeof(struct ipt_stat);
	int sock = -1;
	int ret = 0;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0)
	{
		dprintf("create socket failed\n");
		ret = -1;
		goto out;
	}

	ret = getsockopt(sock, IPPROTO_IP, IPT_STAT_GET_WAN_STAT, stat, &len);
	if (ret != 0)
	{
		dprintf("setsockopt failed to get stats\n");
		goto out;
	}
	else if (len != sizeof(struct ipt_stat))
	{
		dprintf("len %d != %d\n", len, sizeof(struct ipt_stat));
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	if (sock > -1)
	{
		close(sock);
	}
	return ret;
}

static int
connect_ipt_outgone()
{
	struct ipt_stat ipts;
	int ret = 0;

	ret = connect_ipt_stat(&ipts);
	if (ret != 0)
	{
		return 0;
	}

	dprintf("old/new send pkts: %lld, %lld\n", last_stat.snd_pkt, ipts.snd_pkt);
	if (ipts.snd_pkt != 0 && ipts.snd_pkt > last_stat.snd_pkt)
	{
		ret = 1;
	}
	memcpy(&last_stat, &ipts, sizeof(struct ipt_stat));

	return ret;
}

static int
connect_cfg_ip4addr(const char *secname, const char *name, uint32_t *ip4addr)
{
	const char *val = NULL;
	struct in_addr addr;
	int ret = 0;

	val = config_option_str(secname, name);
	if (!val) 
	{
		dprintf("interface lan doesn't exist ipaddr\n");
		ret = -1;
		goto out;
	}

	ret = inet_aton(val, &addr);
	if (ret == 0)
	{
		ret = -1;
		dprintf("Invalid lan ipaddr\n");
		goto out;
	}

	*ip4addr = ntohl(addr.s_addr);
	ret = 0;

out:
	return ret;
}

static int 
connect_ipt_init()
{
	struct ipt_net ipnet;
	int sock = -1;
	int ret = 0;

#if 0
	ret = system_if_get_addr(CONNECT_IFNAME_LAN, &ipnet.ip);
	if (ret != 0)
	{
		dprintf("system_if_get_addr(lan) failed\n");
		goto out;
	}

	ret = system_if_get_mask(CONNECT_IFNAME_LAN, &ipnet.mask);
	if (ret != 0)
	{
		dprintf("system_if_get_mask(lan) failed\n");
		goto out;
	}

#else
	ret = connect_cfg_ip4addr(CONNECT_IFACE_LAN, "ipaddr", &ipnet.ip);
	if (ret != 0)
	{
		goto out;
	}

	ret = connect_cfg_ip4addr(CONNECT_IFACE_LAN, "netmask", &ipnet.mask);
	if (ret != 0)
	{
		goto out;
	}
#endif

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) 
	{
		dprintf("create socket failed\n");
		ret = -1;
		goto out;
	}

	ret = setsockopt(sock, IPPROTO_IP, IPT_STAT_DEL_ALL, NULL, 0);
	if (ret != 0)
	{
		dprintf("setsockopt stats del all failed");
		goto out;
	}

	ret = setsockopt(sock, IPPROTO_IP, IPT_STAT_SET_NET, &ipnet, sizeof(ipnet));
	if (ret != 0)
	{
		dprintf("setsockopt stats set net failed");
		goto out;
	}

	ret = 0;

out:
	if (sock > -1)
	{
		close(sock);
	}
	return ret;
}

void 
connect_dump_info(struct blob_buf *b)
{
	blobmsg_add_u32(b, "timeout remaining", uloop_timeout_remaining(&timeout));
}

int 
connect_init()
{
	int ret = 0;

	if (initialized)
	{
		return ret;
	}

	ret = connect_ipt_init();
	if (ret != 0)
	{
		dprintf("connect_ipt_init failed\n");
		return ret;
	}

	(void)connect_ipt_stat(&last_stat);

	timeout.cb = connect_timeout;
	ret = uloop_timeout_set(&timeout, CONNECT_TIMEOUT);

	initialized = 1;
	return ret;
}

void 
connect_exit()
{
	if (initialized)
	{
		uloop_timeout_cancel(&timeout);
		/* delete default route */
		connect_dft_route(0);
		initialized = 0;
	}
}

