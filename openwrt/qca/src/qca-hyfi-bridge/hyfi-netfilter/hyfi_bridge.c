/*
 *  QCA HyFi Bridge
 *
 * Copyright (c) 2012, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/etherdevice.h>
#include "mc_private.h"
#include "mc_snooping.h"
#include "hyfi_netfilter.h"
#include "hyfi_hatbl.h"
#include "hyfi_hdtbl.h"
#include "hyfi_api.h"
#include "hyfi_hash.h"
#include "hyfi_seamless.h"
#include "hyfi_aggr.h"
#include "queue.h"

/* Default Linux bridge */
static char hyfi_linux_bridge[IFNAMSIZ] = "";

/* This parameter can be set from the insmod command line */
MODULE_PARM_DESC(hyfi_linux_bridge, "Default Hy-Fi managed bridge");

static struct hyfi_net_bridge hyfi_br __read_mostly;
static int hyfi_bridge_ports_init(struct net_device *br_dev);
static int hyfi_bridge_init_bridge_device(const char *br_name);
static int hyfi_bridge_deinit_bridge_device(void);
static int hyfi_bridge_del_ports(void);
static void hyfi_destroy_port_rcu(struct rcu_head *head);

int hyfi_bridge_set_bridge_name(const char *br_name)
{
	int retval = 0;

	spin_lock_bh(&hyfi_br.lock);

	if (!br_name) {
		if (hyfi_br.dev) {
			/* Detach from existing bridge */
			hyfi_bridge_deinit_bridge_device();
			hyfi_linux_bridge[0] = 0;
		}

		spin_unlock_bh(&hyfi_br.lock);
		return 0;
	}

	if (hyfi_br.dev && !strcmp(hyfi_br.dev->name, br_name)) {
		/* Bridge already attached */
		spin_unlock_bh(&hyfi_br.lock);
		return 0;
	}

	if (hyfi_br.dev) {
		/* Detach from existing bridge */
		hyfi_bridge_deinit_bridge_device();
		hyfi_linux_bridge[0] = 0;
	}

	/* Update new bridge */
	hyfi_bridge_init_bridge_device(br_name);

	spin_unlock_bh(&hyfi_br.lock);
	return retval;
}

const char *hyfi_bridge_get_bridge_name(void)
{
	if (!hyfi_linux_bridge[0])
		return NULL ;

	return hyfi_linux_bridge;
}

int hyfi_bridge_dev_event(unsigned long event, struct net_device *dev)
{
	spin_lock_bh(&hyfi_br.lock);

	if (hyfi_br.dev && dev != hyfi_br.dev) {
		spin_unlock_bh(&hyfi_br.lock);
		return -1;
	}

	switch (event) {
	case NETDEV_DOWN:
		if (!hyfi_br.dev)
			break;

		DPRINTK("Interface %s is down, ptr = %p\n", dev->name, dev);

		/* Free the hold of the device */
		hyfi_bridge_deinit_bridge_device();
		break;

	case NETDEV_UP:
		if (dev == hyfi_br.dev)
			break;

		if (!strcmp(dev->name, hyfi_linux_bridge)) {
			DPRINTK("Interface %s is up, ptr = %p\n", dev->name, dev);

			if (dev->priv_flags != IFF_EBRIDGE) {
				printk(KERN_ERR "hyfi-bridging: Device %s is NOT a bridge!\n", dev->name);
			} else {
				if (hyfi_bridge_init_bridge_device(hyfi_linux_bridge)) {
					printk(KERN_ERR "hyfi-bridging: Failed to initialize device %s\n", dev->name);
					hyfi_br.dev = NULL;
				}
			}
		}
		break;

	case NETDEV_CHANGE:
	    break;

	default:
		break;
	}

	spin_unlock_bh(&hyfi_br.lock);
	return 0;
}

static int hyfi_bridge_del_ports(void)
{
	struct hyfi_net_bridge_port *hyfi_p;

	list_for_each_entry_rcu(hyfi_p, &hyfi_br.port_list, list) {
		list_del_rcu(&hyfi_p->list);
		call_rcu(&hyfi_p->rcu, hyfi_destroy_port_rcu);
	}

	return 0;
}

int hyfi_bridge_init_port(struct net_bridge_port *p)
{
	struct hyfi_net_bridge_port *hyfi_p;

	/* First, look up this port in our list */
	hyfi_p = hyfi_bridge_get_port(p);

	if (hyfi_p) {
		/* Update the device pointer */
		hyfi_p->dev = p->dev;
		return 0;
	}

	/* Not found - create a new Hy-Fi port entry */
	hyfi_p = kzalloc(sizeof(struct hyfi_net_bridge_port), GFP_ATOMIC);

	if (!hyfi_p) {
		printk(KERN_ERR "hyfi: Failed to allocate memory for port\n");
		return -1;
	}

	hyfi_p->bcast_enable = 0;
	hyfi_p->group_num = HYFI_PORTGRP_INVALID;
	hyfi_p->group_type = !HYFI_PORTGRP_TYPE_RELAY;
	hyfi_p->port_type = HYFI_PORT_INVALID_TYPE;
	hyfi_p->dev = p->dev;

	list_add_rcu(&hyfi_p->list, &hyfi_br.port_list);
	printk(KERN_INFO "hyfi: Added interface %s\n", p->dev->name);

	return 0;
}

static void hyfi_destroy_port_rcu(struct rcu_head *head)
{
	struct hyfi_net_bridge_port *hyfi_p =
			container_of(head, struct hyfi_net_bridge_port, rcu);

	printk(KERN_INFO "hyfi: Removed interface %s\n", hyfi_p->dev->name);
	kfree(hyfi_p);
}

int hyfi_bridge_delete_port(struct net_bridge_port *p)
{
	struct hyfi_net_bridge_port *hyfi_p;

	if (unlikely(!p))
		return 0;

	list_for_each_entry_rcu(hyfi_p, &hyfi_br.port_list, list) {
		if (hyfi_p->dev == p->dev) {
			list_del_rcu(&hyfi_p->list);
			call_rcu(&hyfi_p->rcu, hyfi_destroy_port_rcu);
			return 0;
		}
	}

	return 0;
}

struct hyfi_net_bridge_port *hyfi_bridge_get_port(const struct net_bridge_port *p)
{
	struct hyfi_net_bridge_port *hyfi_p;

	if (unlikely(!p))
		return NULL;

	list_for_each_entry_rcu(hyfi_p, &hyfi_br.port_list, list) {
		if (hyfi_p->dev == p->dev) {
			return hyfi_p;
		}
	}

	return NULL;
}

struct hyfi_net_bridge_port *hyfi_bridge_get_port_by_dev(const struct net_device *dev)
{
	struct hyfi_net_bridge_port *hyfi_p;

	if (unlikely(!dev))
		return NULL;

	list_for_each_entry_rcu(hyfi_p, &hyfi_br.port_list, list) {
		if (hyfi_p->dev == dev) {
			return hyfi_p;
		}
	}

	return NULL;
}

static int hyfi_bridge_ports_init(struct net_device *br_dev)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);

	dev = first_net_device(&init_net);
	while (dev) {
		struct net_bridge_port *br_port = hyfi_br_port_get(dev);
		if (br_port && br_port->br) {
		    if (br_port->br->dev == br_dev) {
                /* Add to bridge port extended member */
                hyfi_bridge_init_port(br_port);
		    }
		}

		dev = next_net_device(dev);
	}

	read_unlock(&dev_base_lock);

	return 0;
}

struct hyfi_net_bridge *hyfi_bridge_get(const struct net_bridge *br)
{
	if (hyfi_br.dev && (!br || br->dev == hyfi_br.dev))
		return &hyfi_br;

	return NULL;
}

struct hyfi_net_bridge *hyfi_bridge_get_by_dev(const struct net_device *dev)
{
	struct net_bridge_port *br_port;
	const struct net_device *br_dev;

	if (unlikely(!hyfi_br.dev || !dev))
		return NULL;

	if (dev->priv_flags & IFF_EBRIDGE) {
		br_dev = dev;
	} else {
		br_port = hyfi_br_port_get(dev);

		if (!br_port)
			return NULL;

		br_dev = br_port->br->dev;
	}

	if (br_dev == hyfi_br.dev)
		return &hyfi_br;

	return NULL;
}

static inline struct net_bridge_port *hyfi_bridge_handle_ha(struct net_hatbl_entry *ha,
		struct sk_buff **skb)
{
	struct net_bridge_port *dst;

	if (likely(ha->dst->dev)) {
		if ( hyfi_ha_has_flag(ha,
				HYFI_HACTIVE_TBL_AGGR_TX_ENTRY)) {
			dst = hyfi_aggr_handle_tx_path(ha, skb);
		} else {
			dst = ha->dst;
		}
		ha->num_packets++;
		ha->num_bytes += (*skb)->len;
		hyfi_ha_clear_flag(ha, HYFI_HACTIVE_TBL_ACCL_ENTRY);

		if (hyfi_br.path_switch_param.enable_path_switch
				&& (ha->flags & HYFI_HACTIVE_TBL_SEAMLESS_ENABLED)) {
			hyfi_psw_pkt_track(*skb, ha, HYFI_FORWARD_PKT);

			if ((ha->psw_stm_entry.tx_pkt_cnt++
					& (HYFI_PSW_PKT_CNT - 1)) == 0) {
				hyfi_psw_send_pkt(&hyfi_br, ha, HYFI_PSW_PKT_5, 0);
			}
		}

		return dst;
	}

	hyfi_hatbl_delete_by_port(&hyfi_br, ha->dst);
	return NULL;
}

static inline struct net_bridge_port *hyfi_bridge_handle_hd(struct net_hdtbl_entry *hd,
		struct sk_buff **skb, u_int32_t hash, u_int32_t traffic_class, u_int32_t priority)
{
	struct net_hatbl_entry *ha = hyfi_hatbl_insert(&hyfi_br, hash,
			traffic_class, hd, priority,
			eth_hdr(*skb)->h_source);

	if (unlikely(!ha))
		return NULL;

	ha->num_packets++;
	ha->num_bytes += (*skb)->len;
	return ha->dst;
}

static struct net_bridge_port *hyfi_bridge_handle_aggr(struct net_hatbl_entry *ha,
		struct sk_buff **skb, u_int16_t seq)
{
	/* Untag the packet */
	hyfi_aggr_untag_packet(*skb);

	if (unlikely(seq == (u_int16_t)~0)) {
		if (!ha->aggr_rx_entry->aggr_new_flow) {
			hyfi_aggr_end(ha);
		}

		/* We already received tagged packets on this flow,
		 * but still receiving older packets from the other
		 * interface. Need to forward them.
		 */
		return ha->dst;
	}

	if (unlikely(!hyfi_ha_has_flag(ha, HYFI_HACTIVE_TBL_AGGR_RX_ENTRY))) {
		/* New entry:
		 * Always start an entry with seq = 0 because we could receive
		 * older packets later due to different interface latency.
		 */
		if(hyfi_aggr_init_entry(ha, seq) == 0) {
			hyfi_ha_clear_flag(ha, HYFI_HACTIVE_TBL_TRACKED_ENTRY);
		} else {
			return ha->dst;
		}
	}

	/* Process the packet and return destination.
	 */
	return hyfi_aggr_process_pkt(ha, skb, seq);
}

struct net_bridge_port *hyfi_bridge_get_dst(const struct net_bridge_port *src,
		struct sk_buff **skb)
{
	/* hybrid look up first */
	u_int32_t flag, priority;
	u_int32_t hash;
	u_int32_t traffic_class;
	struct net_hatbl_entry *ha = NULL;
	struct net_hdtbl_entry *hd;
	struct net_bridge_fdb_entry *dst;
	u_int16_t seq = ~0;
	const struct net_bridge *br;

	if (src) {
		/* Bridged interface */
		br = src->br;
	} else {
		/* Routed interface */
		br = netdev_priv(BR_INPUT_SKB_CB(*skb)->brdev);
	}

	if (unlikely(!br || !hyfi_br.dev || br->dev != hyfi_br.dev))
		return NULL;

	if (unlikely(hyfi_hash_skbuf(*skb, &hash, &flag, &priority, &seq)))
		return NULL;

	traffic_class = (flag & IS_IPPROTO_UDP) ?
			HYFI_TRAFFIC_CLASS_UDP : HYFI_TRAFFIC_CLASS_OTHER;

	/* If incoming packet is a TCP stream, make sure that the TCP-ACK
	 * stream will be transmitted back on the same medium (if hyfi_tcp_sp
	 * is enabled).
	 */
	if (src && (flag & IS_IPPROTO_TCP) && hyfi_tcp_sp(&hyfi_br) &&
			!hyfi_portgrp_relay(hyfi_bridge_get_port(src)) &&
			(hd = __hyfi_hdtbl_get(&hyfi_br, eth_hdr(*skb)->h_source))) {
				hyfi_hatbl_update_local(&hyfi_br, hash,eth_hdr(*skb)->h_source,
						eth_hdr(*skb)->h_dest, hd, (struct net_bridge_port *)src,
						HYFI_TRAFFIC_CLASS_OTHER, priority, flag);
	}

	/* First, look up in the H-Active table. If not exists, look up in
	 * the H-Default table. Finally, if not in there, look up in the FDB. */
	ha = __hyfi_hatbl_get(&hyfi_br, hash, eth_hdr(*skb)->h_dest,
			traffic_class, priority);

	if (ha) {
		/* Entry found, update stats, and return destination port */
		if (!hyfi_ha_has_flag(ha, HYFI_HACTIVE_TBL_RX_ENTRY)) {
			return hyfi_bridge_handle_ha(ha, skb);
		}
	} else if ((hd = __hyfi_hdtbl_get(&hyfi_br, eth_hdr(*skb)->h_dest))) {
		/* Create a new entry based on H-Default table */
		return hyfi_bridge_handle_hd(hd, skb, hash, traffic_class, priority);
	} else if ((dst = os_br_fdb_get((struct net_bridge *)br, eth_hdr(*skb)->h_dest)) && !dst->is_local) {
        hyfi_hatbl_insert_from_fdb(&hyfi_br, hash, dst->dst, eth_hdr(*skb)->h_source,
                eth_hdr(*skb)->h_dest, br->dev->dev_addr,
                traffic_class, priority);

		return dst->dst;
	}

	/* This section handles the tracked flows case.
	 * Handle each case separately.
	 */
	if (ha) {
		if (flag & IS_HYFI_AGGR_FLOW) {
			return hyfi_bridge_handle_aggr(ha, skb, seq);
		}

		if(hyfi_ha_has_flag(ha, HYFI_HACTIVE_TBL_TRACKED_ENTRY)) {
			if(!hyfi_psw_process_pkt(ha, skb, &hyfi_br))
				return ha->dst;

			return (struct net_bridge_port *) -1;
		}

		if(unlikely(IS_IFACE_THROTTLED(ha))) {
			hyfi_psw_throttle(&hyfi_br, ha, skb, HYFI_FORWARD_PKT);
			return ha->dst;
		}
	}

	if(unlikely(flag & (IS_HYFI_PKT | IS_HYFI_IP_PKT))) {
		hyfi_psw_process_hyfi_pkt(&hyfi_br, *skb, flag);

		if(hyfi_br.path_switch_param.drop_markers) {
			kfree_skb(*skb);
			*skb = NULL;
			return (struct net_bridge_port *) -1;
		}

		return NULL;
	}

	if(unlikely(flag & IS_HYFI_AGGR_FLOW)) {
		hyfi_aggr_untag_packet(*skb);

		if(seq == (u_int16_t)~0) {
			return NULL;
		}

		ha = hyfi_hatbl_create_aggr_entry(&hyfi_br, hash, eth_hdr(*skb)->h_source,
				eth_hdr(*skb)->h_dest, traffic_class, priority, seq);

		if(!ha) {
			if(printk_ratelimit())
				printk(KERN_ERR"hyfi: Cannot create an entry for aggregated flow\n");

			return NULL;
		}

		/* If sequence == 0, then it means we received the first transmitted
		 * packet from the other side in the correct order.
		 */
		return hyfi_aggr_process_pkt(ha, skb, seq);
	}

	return NULL;
}

int hyfi_bridge_should_deliver(const struct hyfi_net_bridge_port *src,
		const struct hyfi_net_bridge_port *dst, const struct sk_buff *skb)
{
	if (likely(src && dst)) {
		if (!hyfi_portgrp_relay(src)) {
			/* For non-relay group, allow forwarding only to other groups */
			return ((src->group_num != dst->group_num) &&
					(dst->group_num != HYFI_PORTGRP_INVALID));
		}
	}

	/* Allow forwarding otherwise */
	return 1;
}

static int hyfi_bridge_deinit_bridge_device(void)
{
	struct net_device *br_dev;

	/* Detach from existing bridge */
	br_dev = hyfi_br.dev;

	if (!br_dev) {
		return -1;
	}

	br_dev->needed_headroom -= 80;

	/* Multicast module detach to the bridge */
	mc_detach(&hyfi_br);

	rcu_assign_pointer(br_get_dst_hook, NULL);

	hyfi_bridge_del_ports();

	hyfi_hatbl_flush(&hyfi_br);
	hyfi_hdtbl_flush(&hyfi_br);

	dev_put(hyfi_br.dev);
	hyfi_br.dev = NULL;

	printk(KERN_INFO"hyfi: Bridge %s is now detached\n", br_dev->name);
	return 0;
}

static int hyfi_bridge_init_bridge_device(const char *br_name)
{
	struct net_device *br_dev;

	if (!br_name) {
		return -1;
	}

	br_dev = dev_get_by_name(&init_net, br_name);

	if (!br_dev) {
		strlcpy(hyfi_linux_bridge, br_name, IFNAMSIZ);
		return 0;
	}

	strlcpy(hyfi_linux_bridge, br_name, IFNAMSIZ);

	/* Default bridge configuration */
	hyfi_br.flags = HYFI_BRIDGE_FLAG_MODE_RELAY_OVERRIDE
			| HYFI_BRIDGE_FLAG_MODE_TCP_SP;

	br_dev->needed_headroom += 80;

	/* Init ports */
	hyfi_bridge_ports_init(br_dev);
	hyfi_br.dev = br_dev;

	/* see br_input.c */
	rcu_assign_pointer(br_get_dst_hook, hyfi_bridge_get_dst);

	/* Multicast module attach to the bridge */
	mc_attach(&hyfi_br);

	printk(KERN_INFO"hyfi: Bridge %s is now attached\n", br_dev->name);

	return 0;
}

int __init hyfi_bridge_init(void)
{
	memset(&hyfi_br, 0, sizeof(struct hyfi_net_bridge));

	spin_lock_init(&hyfi_br.lock);

	hyfi_br.event_pid = NLEVENT_INVALID_PID;
	INIT_LIST_HEAD(&hyfi_br.port_list);

	/* Init tables */
	if (hyfi_hatbl_init(&hyfi_br))
		return -1;

	if (hyfi_hdtbl_init()) {
		hyfi_hatbl_fini(&hyfi_br);
		return -1;
	}

	/* Init seamless path switching */
	hyfi_psw_init(&hyfi_br);

	return 0;
}

void __exit hyfi_bridge_fini(void)
{
	hyfi_bridge_set_bridge_name(NULL);

	hyfi_hatbl_fini(&hyfi_br);
	hyfi_hdtbl_fini(&hyfi_br);
}
