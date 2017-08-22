/*
 **************************************************************************
 * Copyright (c) 2014,2015 The Linux Foundation.  All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/pkt_sched.h>
#include <linux/string.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/unaligned.h>
#include <asm/uaccess.h>	/* for put_user */
#include <net/ipv6.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <net/arp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#ifdef ECM_INTERFACE_VLAN_ENABLE
#include <linux/../../net/8021q/vlan.h>
#include <linux/if_vlan.h>
#endif

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_FRONT_END_IPV4_DEBUG_LEVEL

#include <nss_api_if.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_datagram.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_classifier_default.h"
#ifdef ECM_CLASSIFIER_NL_ENABLE
#include "ecm_classifier_nl.h"
#endif
#ifdef ECM_CLASSIFIER_HYFI_ENABLE
#include "ecm_classifier_hyfi.h"
#endif
#include "ecm_classifier_dscp.h"
#ifdef ECM_CLASSIFIER_PCC_ENABLE
#include "ecm_classifier_pcc.h"
#endif
#include "ecm_interface.h"

/*
 * Magic numbers
 */
#define ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC 0xEB12
#define ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC 0xEA67
#define ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC 0xEC34

/*
 * struct ecm_front_end_ipv4_connection_tcp_instance
 *	A connection specific front end instance for TCP connections
 */
struct ecm_front_end_ipv4_connection_tcp_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */
	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */
	bool can_accel;						/* RO: True when the connection can be accelerated */
	bool is_defunct;					/* True if the connection has become defunct */
	ecm_front_end_acceleration_mode_t accel_mode;		/* Indicates  the type of acceleration being applied to a connection, if any. */
	spinlock_t lock;					/* Lock for structure data */
	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * struct ecm_front_end_ipv4_connection_udp_instance
 *	A connection specific front end instance for UDP connections
 */
struct ecm_front_end_ipv4_connection_udp_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */
	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */
	bool can_accel;						/* RO: True when the connection can be accelerated */
	bool is_defunct;					/* True if the connection has become defunct */
	ecm_front_end_acceleration_mode_t accel_mode;		/* Indicates the type of acceleration being applied to a connection, if any. */
	spinlock_t lock;					/* Lock for structure data */
	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * struct ecm_front_end_ipv4_connection_non_ported_instance
 *	A connection specific front end instance for Non-Ported connections
 */
struct ecm_front_end_ipv4_connection_non_ported_instance {
	struct ecm_front_end_connection_instance base;		/* Base class */
	struct ecm_db_connection_instance *ci;			/* RO: The connection instance relating to this instance. */
	bool can_accel;						/* RO: True when the connection can be accelerated */
	bool is_defunct;					/* True if the connection has become defunct */
	ecm_front_end_acceleration_mode_t accel_mode;		/* Indicates the type of acceleration being applied to a connection, if any. */
	spinlock_t lock;					/* Lock for structure data */
	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

static int ecm_front_end_ipv4_no_action_limit_default = 250;		/* Default no-action limit. */
static int ecm_front_end_ipv4_driver_fail_limit_default = 250;		/* Default driver fail limit. */
static int ecm_front_end_ipv4_nack_limit_default = 250;			/* Default nack limit. */
static int ecm_front_end_ipv4_udp_accelerated_count = 0;		/* Number of UDP connections currently offloaded */
static int ecm_front_end_ipv4_tcp_accelerated_count = 0;		/* Number of TCP connections currently offloaded */
static int ecm_front_end_ipv4_non_ported_accelerated_count = 0;		/* Number of Non-Ported connections currently offloaded */
static int ecm_front_end_ipv4_accelerated_count = 0;			/* Total offloads */

/*
 * Locking of the classifier - concurrency control for file global parameters.
 * NOTE: It is safe to take this lock WHILE HOLDING a feci->lock.  The reverse is NOT SAFE.
 */
static spinlock_t ecm_front_end_ipv4_lock;			/* Protect against SMP access between netfilter, events and private threaded function. */

/*
 * System device linkage
 */
static struct device ecm_front_end_ipv4_dev;		/* System device linkage */

/*
 * General operational control
 */
static int ecm_front_end_ipv4_stopped = 0;			/* When non-zero further traffic will not be processed */

/*
 * Management thread control
 */
static bool ecm_front_end_ipv4_terminate_pending = false;		/* True when the user has signalled we should quit */

/*
 * NSS driver linkage
 */
static struct nss_ctx_instance *ecm_front_end_ipv4_nss_ipv4_mgr = NULL;

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;
extern int nf_ct_tcp_be_liberal;

/*
 * ecm_front_end_ipv4_node_establish_and_ref()
 *	Returns a reference to a node, possibly creating one if necessary.
 *
 * The given_node_addr will be used if provided.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_node_instance *ecm_front_end_ipv4_node_establish_and_ref(struct net_device *dev, ip_addr_t addr,
							struct ecm_db_iface_instance *interface_list[], int32_t interface_list_first,
							uint8_t *given_node_addr)
{
	struct ecm_db_node_instance *ni;
	struct ecm_db_node_instance *nni;
	struct ecm_db_iface_instance *ii;
	int i;
	bool done;
	uint8_t node_addr[ETH_ALEN];

	DEBUG_INFO("Establish node for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));

	/*
	 * The node is the datalink address, typically a MAC address.
	 * However the node address to use is not always obvious and depends on the interfaces involved.
	 * For example if the interface is PPPoE then we use the MAC of the PPPoE server as we cannot use normal ARP resolution.
	 * Not all hosts have a node address, where there is none, a suitable alternative should be located and is typically based on 'addr'
	 * or some other datalink session information.
	 * It should be, at a minimum, something that ties the host with the interface.
	 *
	 * Iterate from 'inner' to 'outer' interfaces - discover what the node is.
	 */
	memset(node_addr, 0, ETH_ALEN);
	done = false;
	if (given_node_addr) {
		memcpy(node_addr, given_node_addr, ETH_ALEN);
		done = true;
		DEBUG_TRACE("Using given node address: %pM\n", node_addr);
	}
	for (i = ECM_DB_IFACE_HEIRARCHY_MAX - 1; (!done) && (i >= interface_list_first); i--) {
		ecm_db_iface_type_t type;
		ip_addr_t gw_addr = ECM_IP_ADDR_NULL;
		bool on_link = false;
#ifdef ECM_INTERFACE_PPP_ENABLE
		struct ecm_db_interface_info_pppoe pppoe_info;
#endif
		type = ecm_db_connection_iface_type_get(interface_list[i]);
		DEBUG_INFO("Lookup node address, interface @ %d is type: %d\n", i, type);

		switch (type) {

		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * Node address is the address of the remote PPPoE server
			 */
			ecm_db_iface_pppoe_session_info_get(interface_list[i], &pppoe_info);
			memcpy(node_addr, pppoe_info.remote_mac, ETH_ALEN);
			done = true;
			break;
#else
			DEBUG_TRACE("PPPoE interface unsupported\n");
			return NULL;
#endif

		case ECM_DB_IFACE_TYPE_SIT:
		case ECM_DB_IFACE_TYPE_TUNIPIP6:
			done = true;
			break;

		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			/*
			 * VLAN handled same along with ethernet, lag, bridge etc.
			 */
#else
			DEBUG_TRACE("VLAN interface unsupported\n");
			return NULL;
#endif
		case ECM_DB_IFACE_TYPE_ETHERNET:
		case ECM_DB_IFACE_TYPE_LAG:
		case ECM_DB_IFACE_TYPE_BRIDGE:
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			if (!ecm_interface_mac_addr_get(addr, node_addr, &on_link, gw_addr)) {
				__be32 ipv4_addr;
				__be32 src_ip;
				DEBUG_TRACE("failed to obtain node address for host " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));
				/*
				 * Issue an ARP request for it, select the src_ip from which to issue the request.
				 */
				ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, addr);
				src_ip = inet_select_addr(dev, ipv4_addr, RT_SCOPE_LINK);
				if (!src_ip) {
					DEBUG_TRACE("failed to lookup IP for %pI4\n", &ipv4_addr);
					return NULL;
				}

				/*
				 * If we have a GW for this address, then we have to send ARP request to the GW
				 */
				if (!on_link && !ECM_IP_ADDR_IS_NULL(gw_addr)) {
					ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, gw_addr);
				}

				DEBUG_TRACE("Send ARP for %pI4 using src_ip as %pI4\n", &ipv4_addr, &src_ip);
				arp_send(ARPOP_REQUEST, ETH_P_ARP, ipv4_addr, dev, src_ip, NULL, NULL, NULL);

				/*
				 * Unable to get node address at this time.
				 */
				return NULL;
			}
			if (is_multicast_ether_addr(node_addr)) {
				DEBUG_TRACE("multicast node address for host " ECM_IP_ADDR_DOT_FMT ", node_addr: %pM\n", ECM_IP_ADDR_TO_DOT(addr), node_addr);
				return NULL;
			}

			/*
			 * Because we are iterating from inner to outer interface, this interface is the
			 * innermost one that has a node address - take this one.
			 */
			done = true;
			break;
		default:
			/*
			 * Don't know how to handle these.
			 * Just copy some part of the address for now, but keep iterating the interface list
			 * in the hope something recognisable will be seen!
			 * GGG TODO We really need to roll out support for all interface types we can deal with ASAP :-(
			 */
			memcpy(node_addr, (uint8_t *)addr, ETH_ALEN);
		}
	}
	if (!done) {
		DEBUG_INFO("Failed to establish node for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));
		return NULL;
	}

	/*
	 * Locate the node
	 */
	ni = ecm_db_node_find_and_ref(node_addr);
	if (ni) {
		DEBUG_TRACE("%p: node established\n", ni);
		return ni;
	}

	/*
	 * No node - establish iface
	 */
	ii = ecm_interface_establish_and_ref(dev);
	if (!ii) {
		DEBUG_WARN("Failed to establish iface\n");
		return NULL;
	}

	/*
	 * No node - create one
	 */
	nni = ecm_db_node_alloc();
	if (!nni) {
		DEBUG_WARN("Failed to establish node\n");
		ecm_db_iface_deref(ii);
		return NULL;
	}

	/*
	 * Add node into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ni = ecm_db_node_find_and_ref(node_addr);
	if (ni) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_node_deref(nni);
		ecm_db_iface_deref(ii);
		return ni;
	}

	ecm_db_node_add(nni, ii, node_addr, NULL, nni);
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Don't need iface instance now
	 */
	ecm_db_iface_deref(ii);

	DEBUG_TRACE("%p: node established\n", nni);
	return nni;
}

/*
 * ecm_front_end_ipv4_host_establish_and_ref()
 *	Returns a reference to a host, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_host_instance *ecm_front_end_ipv4_host_establish_and_ref(ip_addr_t addr)
{
	struct ecm_db_host_instance *hi;
	struct ecm_db_host_instance *nhi;

	DEBUG_INFO("Establish host for " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(addr));

	/*
	 * Locate the host
	 */
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		DEBUG_TRACE("%p: host established\n", hi);
		return hi;
	}

	/*
	 * No host - create one
	 */
	nhi = ecm_db_host_alloc();
	if (!nhi) {
		DEBUG_WARN("Failed to establish host\n");
		return NULL;
	}

	/*
	 * Add host into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	hi = ecm_db_host_find_and_ref(addr);
	if (hi) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_host_deref(nhi);
		return hi;
	}

	ecm_db_host_add(nhi, addr, true, NULL, nhi);

	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	DEBUG_TRACE("%p: host established\n", nhi);
	return nhi;
}

/*
 * ecm_front_end_ipv4_mapping_establish_and_ref()
 *	Returns a reference to a mapping, possibly creating one if necessary.
 *
 * Returns NULL on failure.
 */
static struct ecm_db_mapping_instance *ecm_front_end_ipv4_mapping_establish_and_ref(ip_addr_t addr, int port)
{
	struct ecm_db_mapping_instance *mi;
	struct ecm_db_mapping_instance *nmi;
	struct ecm_db_host_instance *hi;

	DEBUG_INFO("Establish mapping for " ECM_IP_ADDR_DOT_FMT ":%d\n", ECM_IP_ADDR_TO_DOT(addr), port);

	/*
	 * Locate the mapping
	 */
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		DEBUG_TRACE("%p: mapping established\n", mi);
		return mi;
	}

	/*
	 * No mapping - establish host existence
	 */
	hi = ecm_front_end_ipv4_host_establish_and_ref(addr);
	if (!hi) {
		DEBUG_WARN("Failed to establish host\n");
		return NULL;
	}

	/*
	 * Create mapping instance
	 */
	nmi = ecm_db_mapping_alloc();
	if (!nmi) {
		ecm_db_host_deref(hi);
		DEBUG_WARN("Failed to establish mapping\n");
		return NULL;
	}

	/*
	 * Add mapping into the database, atomically to avoid races creating the same thing
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	mi = ecm_db_mapping_find_and_ref(addr, port);
	if (mi) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		ecm_db_mapping_deref(nmi);
		ecm_db_host_deref(hi);
		return mi;
	}

	ecm_db_mapping_add(nmi, hi, port, NULL, nmi);

	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Don't need the host instance now - the mapping maintains a reference to it now.
	 */
	ecm_db_host_deref(hi);

	/*
	 * Return the mapping instance
	 */
	DEBUG_INFO("%p: mapping established\n", nmi);
	return nmi;
}

/*
 * ecm_front_end_ipv4_connection_tcp_callback()
 *	Callback for handling create ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_tcp_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_create_msg * __attribute__((unused)) nircm = &nim->msg.rule_create;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti;

	/*
	 * Is this a response to a create message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_CREATE_RULE_MSG) {
		DEBUG_ERROR("%p: tcp create callback with improper type: %d, serial: %u\n", nim, nim->cm.type, serial);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: create callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: accelerate response for connection: %p, serial: %u\n", fecti, fecti->ci, serial);
	DEBUG_TRACE("%p: rule_flags: %x, valid_flags: %x\n", fecti, nircm->rule_flags, nircm->valid_flags);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecti, &nircm->tuple.flow_ip, nircm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecti, &nircm->tuple.return_ip, nircm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecti, nircm->tuple.protocol);

	/*
	 * Handle the creation result code.
	 */
	DEBUG_TRACE("%p: response: %d\n", fecti, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		/*
		 * Creation command failed (specific reason ignored).
		 */
		DEBUG_TRACE("%p: accel nack: %d\n", fecti, nim->cm.error);
		spin_lock_bh(&fecti->lock);
		DEBUG_ASSERT(fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecti->accel_mode);
		fecti->base.stats.nss_nack++;
		fecti->base.stats.nss_nack_total++;
		if (fecti->base.stats.nss_nack >= fecti->base.stats.nss_nack_limit) {
			/*
			 * Too many NSS rejections
			 */
			fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NSS;
		} else {
			/*
			 * Revert to decelerated
			 */
			fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		}

		/*
		 * Clear any decelerate pending flag since we aren't accelerated anyway we can just clear this whether it is set or not
		 */
		fecti->base.stats.decelerate_pending = false;

		/*
		 * If connection is now defunct then set mode to ensure no further accel attempts occur
		 */
		if (fecti->is_defunct) {
			fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		}
		spin_unlock_bh(&fecti->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	spin_lock_bh(&fecti->lock);
	DEBUG_ASSERT(fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecti->accel_mode);

	/*
	 * If a flush occured before we got the ACK then our acceleration was effectively cancelled on us
	 * GGG TODO This is a workaround for a NSS message OOO quirk, this should eventually be removed.
	 */
	if (fecti->base.stats.flush_happened) {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		fecti->base.stats.flush_happened = false;

		/*
		 * We are decelerated, clear any pending flag as that is meaningless now.
		 */
		fecti->base.stats.decelerate_pending = false;

		/*
		 * Increement the no-action counter.  Our connectin was decelerated on us with no action occurring.
		 */
		fecti->base.stats.no_action_seen++;
		spin_unlock_bh(&fecti->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	/*
	 * We got an ACK - we are accelerated.
	 */
	fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL;

	/*
	 * Create succeeded, declare that we are accelerated.
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_tcp_accelerated_count++;	/* Protocol specific counter */
	ecm_front_end_ipv4_accelerated_count++;		/* General running counter */
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Clear any nack count
	 */
	fecti->base.stats.nss_nack = 0;

	/*
	 * Decelerate may have been attempted while we were accel pending.
	 * If decelerate is pending then we need to begin deceleration :-(
	 */
	if (!fecti->base.stats.decelerate_pending) {
		/*
		 * Increement the no-action counter, this is reset if offload action is seen
		 */
		fecti->base.stats.no_action_seen++;

		spin_unlock_bh(&fecti->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_INFO("%p: Decelerate was pending\n", ci);
	fecti->base.stats.decelerate_pending = false;
	spin_unlock_bh(&fecti->lock);

	feci->decelerate(feci);

	/*
	 * Release the connection.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accelerate()
 *	Accelerate a connection
 *
 * GGG TODO Refactor this function into a single function that np, udp and tcp
 * can all use and reduce the amount of code!
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr,
									struct nf_conn *ct)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	ip_addr_t addr;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_create_msg *nircm;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;
	uint8_t dest_mac_xlate[ETH_ALEN];
	ecm_db_direction_t ecm_dir;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecti, fecti->ci);
	spin_lock_bh(&fecti->lock);
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecti->accel_mode)) {
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: accel %p failed\n", fecti, fecti->ci);
		return;
	}

	/*
	 * If acceleration mode is anything other than "not accelerated" then ignore.
	 */
	if (fecti->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: Ignoring wrong mode accel for conn: %p\n", fecti, fecti->ci);
		return;
	}
	fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING;
	spin_unlock_bh(&fecti->lock);

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure.
	 * NOTE: We leverage the app_data void pointer to be our 32 bit connection serial number.
	 * When we get it back we re-cast it to a uint32 and do a faster connection lookup.
	 */
	memset(&nim, 0, sizeof(struct nss_ipv4_msg));
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_CREATE_RULE_MSG,
			sizeof(struct nss_ipv4_rule_create_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_tcp_callback,
			(void *)ecm_db_connection_serial_get(fecti->ci));

	nircm = &nim.msg.rule_create;
	nircm->valid_flags = 0;
	nircm->rule_flags = 0;

	/*
	 * Initialize VLAN tag information
	 */
	nircm->vlan_primary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_primary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection, we must have at least one interface in the list to continue
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecti->ci, from_ifaces);
	if (from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in from_interfaces list!\n", fecti);
		goto tcp_accel_bad_rule;
	}

	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecti->ci, to_ifaces);
	if (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in to_interfaces list!\n", fecti);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		goto tcp_accel_bad_rule;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecti, from_nss_iface_id, to_nss_iface_id);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto tcp_accel_bad_rule;
	}

	/*
	 * New rule being created
	 */
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	nircm->conn_rule.flow_interface_num = from_nss_iface_id;
	nircm->conn_rule.return_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecti);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecti, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_in_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecti);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecti, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecti);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecti, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecti);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);

			nircm->pppoe_rule.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecti,
					nircm->pppoe_rule.flow_pppoe_session_id,
					nircm->pppoe_rule.flow_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			DEBUG_TRACE("%p: VLAN\n", fecti);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecti);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_in_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_in_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_in_dev, pr->return_qos_tag);
				dev_put(vlan_in_dev);
				vlan_in_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.ingress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.ingress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecti, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecti, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecti);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecti);
				break;
			}
			nircm->conn_rule.flow_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecti, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecti);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto tcp_accel_bad_rule;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecti);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecti, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_out_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecti);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecti, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecti);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecti, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecti);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			nircm->pppoe_rule.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecti,
				    nircm->pppoe_rule.return_pppoe_session_id,
				    nircm->pppoe_rule.return_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			DEBUG_TRACE("%p: VLAN\n", fecti);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecti);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_out_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_out_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_out_dev, pr->flow_qos_tag);
				dev_put(vlan_out_dev);
				vlan_out_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.egress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.egress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecti, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecti, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecti);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecti);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecti);
				break;
			}
			nircm->conn_rule.return_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecti, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecti);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto tcp_accel_bad_rule;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecti->ci)) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	} else {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Set up the flow and return qos tags
	 */
	nircm->qos_rule.flow_qos_tag = (uint32_t)pr->flow_qos_tag;
	nircm->qos_rule.return_qos_tag = (uint32_t)pr->return_qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	/*
	 * DSCP information?
	 */
	if (pr->process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
		nircm->dscp_rule.flow_dscp = pr->flow_dscp;
		nircm->dscp_rule.return_dscp = pr->return_dscp;
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID;
	}

	/*
	 * Set protocol
	 */
	nircm->tuple.protocol = (int32_t)IPPROTO_TCP;

	/*
	 * The flow_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.flow_ip, addr);

	/*
	 * The return_ip is where the connection is established to, however, in the case of ingress
	 * the return_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.return_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.flow_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.return_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	nircm->tuple.flow_ident = ecm_db_connection_from_port_get(fecti->ci);
	nircm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecti->ci);
	nircm->conn_rule.flow_ident_xlate = ecm_db_connection_from_port_nat_get(fecti->ci);
	nircm->conn_rule.return_ident_xlate = ecm_db_connection_to_port_get(fecti->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecti->ci, (uint8_t *)nircm->conn_rule.flow_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecti->ci, (uint8_t *)nircm->conn_rule.return_mac);

	/*
	 * The dest_mac_xlate is the mac address to replace the pkt.dst_mac when a packet is sent to->from
	 * For bridged connections this does not change.
	 * For routed connections this is the mac of the 'to' node side of the connection.
	 */
	if (ecm_db_connection_is_routed_get(fecti->ci)) {
		ecm_db_connection_to_node_address_get(fecti->ci, dest_mac_xlate);
	} else {
		/*
		 * Bridge flows preserve the MAC addressing
		 */
		memcpy(dest_mac_xlate, (uint8_t *)nircm->conn_rule.return_mac, ETH_ALEN);
	}

	/*
	 * Refer to the Example 2 and 3 in ecm_front_end_ipv4_ip_process() function for egress
	 * and ingress NAT'ed cases. In these cases, the destination node is the one which has the
	 * ip_dest_addr. So, above we get the mac address of this host and use that mac address
	 * for the destination node address in NAT'ed cases.
	 */
	ecm_dir = ecm_db_connection_direction_get(fecti->ci);
	if ((ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT)) {
		memcpy(nircm->conn_rule.return_mac, dest_mac_xlate, ETH_ALEN);
	}

	/*
	 * Get MTU information
	 */
	nircm->conn_rule.flow_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecti->ci);
	nircm->conn_rule.return_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecti->ci);

	/*
	 * Need window scaling and remarking information if available
	 * Start by looking up the conntrack connection
	 */
	if (!ct) {
		/*
		 * No conntrack so no need to check window sequence space
		 */
		DEBUG_TRACE("%p: TCP Accel no ct from conn %p to get window data\n", fecti, fecti->ci);
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	} else {
		spin_lock_bh(&ct->lock);
		DEBUG_TRACE("%p: TCP Accel Get window data from ct %p for conn %p\n", fecti, ct, fecti->ci);

		nircm->tcp_rule.flow_window_scale = ct->proto.tcp.seen[0].td_scale;
		nircm->tcp_rule.flow_max_window = ct->proto.tcp.seen[0].td_maxwin;
		nircm->tcp_rule.flow_end = ct->proto.tcp.seen[0].td_end;
		nircm->tcp_rule.flow_max_end = ct->proto.tcp.seen[0].td_maxend;
		nircm->tcp_rule.return_window_scale = ct->proto.tcp.seen[1].td_scale;
		nircm->tcp_rule.return_max_window = ct->proto.tcp.seen[1].td_maxwin;
		nircm->tcp_rule.return_end = ct->proto.tcp.seen[1].td_end;
		nircm->tcp_rule.return_max_end = ct->proto.tcp.seen[1].td_maxend;
		if (nf_ct_tcp_be_liberal || nf_ct_tcp_no_window_check
				|| (ct->proto.tcp.seen[0].flags & IP_CT_TCP_FLAG_BE_LIBERAL)
				|| (ct->proto.tcp.seen[1].flags & IP_CT_TCP_FLAG_BE_LIBERAL)) {
			nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
		}
		spin_unlock_bh(&ct->lock);
	}

	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_TCP_VALID;

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecti->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecti, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, nircm);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: TCP Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"ingress_inner_vlan_tag: %u\n"
			"egress_inner_vlan_tag: %u\n"
			"ingress_outer_vlan_tag: %u\n"
			"egress_outer_vlan_tag: %u\n"
			"rule_flags: %x\n"
			"valid_flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"flow_qos_tag: %x (%u)\n"
			"return_qos_tag: %x (%u)\n"
			"flow_window_scale: %u\n"
			"flow_max_window: %u\n"
			"flow_end: %u\n"
			"flow_max_end: %u\n"
			"return_window_scale: %u\n"
			"return_max_window: %u\n"
			"return_end: %u\n"
			"return_max_end: %u\n"
			"flow_dscp: %x\n"
			"return_dscp: %x\n",
			fecti,
			fecti->ci,
			nircm->tuple.protocol,
			nircm->conn_rule.flow_mtu,
			nircm->conn_rule.return_mtu,
			&nircm->tuple.flow_ip, nircm->tuple.flow_ident,
			&nircm->tuple.return_ip, nircm->tuple.return_ident,
			&nircm->conn_rule.flow_ip_xlate, nircm->conn_rule.flow_ident_xlate,
			&nircm->conn_rule.return_ip_xlate, nircm->conn_rule.return_ident_xlate,
			nircm->conn_rule.flow_mac,
			nircm->conn_rule.return_mac,
			nircm->conn_rule.flow_interface_num,
			nircm->conn_rule.return_interface_num,
			nircm->vlan_primary_rule.ingress_vlan_tag,
			nircm->vlan_primary_rule.egress_vlan_tag,
			nircm->vlan_secondary_rule.ingress_vlan_tag,
			nircm->vlan_secondary_rule.egress_vlan_tag,
			nircm->rule_flags,
			nircm->valid_flags,
			nircm->pppoe_rule.return_pppoe_session_id,
			nircm->pppoe_rule.return_pppoe_remote_mac,
			nircm->pppoe_rule.flow_pppoe_session_id,
			nircm->pppoe_rule.flow_pppoe_remote_mac,
			nircm->qos_rule.flow_qos_tag, nircm->qos_rule.flow_qos_tag,
			nircm->qos_rule.return_qos_tag, nircm->qos_rule.return_qos_tag,
			nircm->tcp_rule.flow_window_scale,
			nircm->tcp_rule.flow_max_window,
			nircm->tcp_rule.flow_end,
			nircm->tcp_rule.flow_max_end,
			nircm->tcp_rule.return_window_scale,
			nircm->tcp_rule.return_max_window,
			nircm->tcp_rule.return_end,
			nircm->tcp_rule.return_max_end,
			nircm->dscp_rule.flow_dscp,
			nircm->dscp_rule.return_dscp);

	/*
	 * Ref the connection before issuing an NSS rule
	 * This ensures that when the NSS responds to the command - which may even be immediately -
	 * the callback function can trust the correct ref was taken for its purpose.
	 * NOTE: remember that this will also implicitly hold the feci.
	 */
	ecm_db_connection_ref(fecti->ci);

	/*
	 * Call the rule create function
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecti->lock);
		DEBUG_ASSERT(fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecti, fecti->accel_mode);
		fecti->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * Release that ref!
	 */
	ecm_db_connection_deref(fecti->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecti->lock);
	DEBUG_ASSERT(fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecti, fecti->accel_mode);
	fecti->base.stats.driver_fail_total++;
	fecti->base.stats.driver_fail++;
	if (fecti->base.stats.driver_fail >= fecti->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Accel failed - driver fail limit\n", fecti);
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecti->lock);
	return;

tcp_accel_bad_rule:
	;

	/*
	 * Jump to here when rule data is bad and an offload command cannot be constructed
	 */
	DEBUG_WARN("%p: Accel failed - bad rule\n", fecti);
	spin_lock_bh(&fecti->lock);
	DEBUG_ASSERT(fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecti, fecti->accel_mode);
	fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_RULE;
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_destroy_callback()
 *	Callback for handling destroy ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_tcp_destroy_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_destroy_msg * __attribute__((unused))nirdm = &nim->msg.rule_destroy;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti;

	/*
	 * Is this a response to a destroy message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_DESTROY_RULE_MSG) {
		DEBUG_ERROR("%p: tcp destroy callback with improper type: %d\n", nim, nim->cm.type);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: destroy callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: decelerate response for connection: %p\n", fecti, fecti->ci);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecti, &nirdm->tuple.flow_ip, nirdm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecti, &nirdm->tuple.return_ip, nirdm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecti, nirdm->tuple.protocol);

	spin_lock_bh(&fecti->lock);

	/*
	 * If decel is not still pending then it's possible that the NSS ended acceleration by some other reason e.g. flush
	 * In which case we cannot rely on the response we get here.
	 */
	if (fecti->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecti->lock);

		/*
		 * Release the connections.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_TRACE("%p: response: %d\n", fecti, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DECEL;
	} else {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}

	/*
	 * If connection became defunct then set mode so that no further accel/decel attempts occur.
	 */
	if (fecti->is_defunct) {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
	}
	spin_unlock_bh(&fecti->lock);

	/*
	 * TCP acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_tcp_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_tcp_accelerated_count >= 0, "Bad udp accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Release the connections.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_destroy_msg *nirdm;
	ip_addr_t addr;
	nss_tx_status_t nss_tx_status;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	/*
	 * If decelerate is in error or already pending then ignore
	 */
	spin_lock_bh(&fecti->lock);
	if (fecti->base.stats.decelerate_pending) {
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If acceleration is pending then we cannot decelerate right now or we will race with it
	 * Set a decelerate pending flag that will be actioned when the acceleration command is complete.
	 */
	if (fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecti->base.stats.decelerate_pending = true;
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * Can only decelerate if accelerated
	 * NOTE: This will also deny accel when the connection is in fail condition too.
	 */
	if (fecti->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * Initiate deceleration
	 */
	fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING;
	spin_unlock_bh(&fecti->lock);

	/*
	 * Prepare deceleration message
	 */
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_DESTROY_RULE_MSG,
			sizeof(struct nss_ipv4_rule_destroy_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_tcp_destroy_callback,
			(void *)ecm_db_connection_serial_get(fecti->ci));

	nirdm = &nim.msg.rule_destroy;
	nirdm->tuple.protocol = (int32_t)IPPROTO_TCP;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.flow_ip, addr);
	ecm_db_connection_to_address_nat_get(fecti->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.return_ip, addr);
	nirdm->tuple.flow_ident = ecm_db_connection_from_port_get(fecti->ci);
	nirdm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecti->ci);

	DEBUG_INFO("%p: TCP Connection %p decelerate\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecti, fecti->ci,
			&nirdm->tuple.flow_ip, nirdm->tuple.flow_ident,
			&nirdm->tuple.return_ip, nirdm->tuple.return_ident);

	/*
	 * Take a ref to the feci->ci so that it will persist until we get a response from the NSS.
	 * NOTE: This will implicitly hold the feci too.
	 */
	ecm_db_connection_ref(fecti->ci);

	/*
	 * Destroy the NSS connection cache entry.
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecti->lock);
		fecti->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * Release the ref take, NSS driver did not accept our command.
	 */
	ecm_db_connection_deref(fecti->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecti->lock);
	fecti->base.stats.driver_fail_total++;
	fecti->base.stats.driver_fail++;
	if (fecti->base.stats.driver_fail >= fecti->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Decel failed - driver fail limit\n", fecti);
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_defunct_callback()
 *	Callback to be called when a TCP connection has become defunct.
 */
static void ecm_front_end_ipv4_connection_tcp_defunct_callback(void *arg)
{
	struct ecm_front_end_connection_instance *feci = (struct ecm_front_end_connection_instance *)arg;
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	spin_lock_bh(&fecti->lock);

	/*
	 * If connection has already become defunct, do nothing.
	 */
	if (fecti->is_defunct) {
		spin_unlock_bh(&fecti->lock);
		return;
	}
	fecti->is_defunct = true;

	/*
	 * If the connection is already in one of the fail modes, do nothing, keep the current accel_mode.
	 */
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecti->accel_mode)) {
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If the connection is decel then ensure it will not attempt accel while defunct.
	 */
	if (fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If the connection is decel pending then decel operation is in progress anyway.
	 */
	if (fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If none of the cases mathes above, this means the connection is in one of the
	 * accel modes (accel or accel_pending) so we force a deceleration.
	 * NOTE: If the mode is accel pending then the decel will be actioned when that is completed.
	 */
	spin_unlock_bh(&fecti->lock);
	ecm_front_end_ipv4_connection_tcp_front_end_decelerate(feci);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get()
 *	Get acceleration state
 */
static ecm_front_end_acceleration_mode_t ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;
	ecm_front_end_acceleration_mode_t state;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	spin_lock_bh(&fecti->lock);
	state = fecti->accel_mode;
	spin_unlock_bh(&fecti->lock);
	return state;
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_action_seen()
 *	Acceleration action / activity has been seen for this connection.
 *
 * NOTE: Call the action_seen() method when the NSS has demonstrated that it has offloaded some data for a connection.
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_action_seen(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	DEBUG_INFO("%p: Action seen\n", fecti);
	spin_lock_bh(&fecti->lock);
	fecti->base.stats.no_action_seen = 0;
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased()
 *	NSS has indicated that acceleration has stopped.
 *
 * NOTE: This is called in response to an NSS self-initiated termination of acceleration.
 * This must NOT be called because the ECM terminated the acceleration.
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	DEBUG_INFO("%p: accel ceased\n", fecti);

	spin_lock_bh(&fecti->lock);

	/*
	 * If we are in accel-pending state then the NSS has issued a flush out-of-order
	 * with the ACK/NACK we are actually waiting for.
	 * To work around this we record a "flush has already happened" and will action it when we finally get that ACK/NACK.
	 * GGG TODO This should eventually be removed when the NSS honours messaging sequence.
	 */
	if (fecti->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecti->base.stats.flush_happened = true;
		fecti->base.stats.flush_happened_total++;
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If connection is no longer accelerated by the time we get here just ignore the command
	 */
	if (fecti->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecti->lock);
		return;
	}

	/*
	 * If the no_action_seen counter was not reset then acceleration ended without any offload action
	 */
	if (fecti->base.stats.no_action_seen) {
		fecti->base.stats.no_action_seen_total++;
	}

	/*
	 * If the no_action_seen indicates successive cessations of acceleration without any offload action occuring
	 * then we fail out this connection
	 */
	if (fecti->base.stats.no_action_seen >= fecti->base.stats.no_action_seen_limit) {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NO_ACTION;
	} else {
		fecti->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}
	spin_unlock_bh(&fecti->lock);

	/*
	 * TCP acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_tcp_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_tcp_accelerated_count >= 0, "Bad tcp accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_tcp_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);
	spin_lock_bh(&fecti->lock);
	fecti->refs++;
	DEBUG_TRACE("%p: fecti ref %d\n", fecti, fecti->refs);
	DEBUG_ASSERT(fecti->refs > 0, "%p: ref wrap\n", fecti);
	spin_unlock_bh(&fecti->lock);
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_tcp_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	spin_lock_bh(&fecti->lock);
	fecti->refs--;
	DEBUG_ASSERT(fecti->refs >= 0, "%p: ref wrap\n", fecti);

	if (fecti->refs > 0) {
		int refs = fecti->refs;
		spin_unlock_bh(&fecti->lock);
		DEBUG_TRACE("%p: fecti deref %d\n", fecti, refs);
		return refs;
	}
	spin_unlock_bh(&fecti->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecti final\n", fecti);
	DEBUG_CLEAR_MAGIC(fecti);
	kfree(fecti);

	/*
	 * Thread may be able to exit on object destruction
	 */
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get()
 *	Return an XML element containing the state of this TCP front end instance
 */
static int ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_front_end_acceleration_mode_t accel_mode;
	struct ecm_front_end_connection_mode_stats stats;
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC, "%p: magic failed", fecti);

	spin_lock_bh(&fecti->lock);
	can_accel = fecti->can_accel;
	accel_mode = fecti->accel_mode;
	memcpy(&stats, &feci->stats, sizeof(struct ecm_front_end_connection_mode_stats));
	spin_unlock_bh(&fecti->lock);

	return snprintf(buf, buf_sz, "<front_end_tcp can_accel=\"%d\" accel_mode=\"%d\" decelerate_pending=\"%d\" flush_happened_total=\"%d\" no_action_seen_total=\"%d\" no_action_seen=\"%d\" no_action_seen_limit=\"%d\""
				" driver_fail_total=\"%d\" driver_fail=\"%d\" driver_fail_limit=\"%d\" nss_nack_total=\"%d\" nss_nack=\"%d\" nss_nack_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			stats.decelerate_pending,
			stats.flush_happened_total,
			stats.no_action_seen_total,
			stats.no_action_seen,
			stats.no_action_seen_limit,
			stats.driver_fail_total,
			stats.driver_fail,
			stats.driver_fail_limit,
			stats.nss_nack_total,
			stats.nss_nack,
			stats.nss_nack_limit);
}

/*
 * ecm_front_end_ipv4_connection_tcp_instance_alloc()
 *	Create a front end instance specific for TCP connection
 */
static struct ecm_front_end_ipv4_connection_tcp_instance *ecm_front_end_ipv4_connection_tcp_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi,
								bool can_accel)
{
	struct ecm_front_end_ipv4_connection_tcp_instance *fecti;

	fecti = (struct ecm_front_end_ipv4_connection_tcp_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_tcp_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecti) {
		DEBUG_WARN("TCP Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecti->refs = 1;
	DEBUG_SET_MAGIC(fecti, ECM_FRONT_END_IPV4_CONNECTION_TCP_INSTANCE_MAGIC);
	spin_lock_init(&fecti->lock);

	fecti->can_accel = can_accel;
	fecti->accel_mode = (can_accel)? ECM_FRONT_END_ACCELERATION_MODE_DECEL : ECM_FRONT_END_ACCELERATION_MODE_FAIL_DENIED;
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	fecti->base.stats.no_action_seen_limit = ecm_front_end_ipv4_no_action_limit_default;
	fecti->base.stats.driver_fail_limit = ecm_front_end_ipv4_driver_fail_limit_default;
	fecti->base.stats.nss_nack_limit = ecm_front_end_ipv4_nack_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecti->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecti->base.ref = ecm_front_end_ipv4_connection_tcp_front_end_ref;
	fecti->base.deref = ecm_front_end_ipv4_connection_tcp_front_end_deref;
	fecti->base.decelerate = ecm_front_end_ipv4_connection_tcp_front_end_decelerate;
	fecti->base.accel_state_get = ecm_front_end_ipv4_connection_tcp_front_end_accel_state_get;
	fecti->base.action_seen = ecm_front_end_ipv4_connection_tcp_front_end_action_seen;
	fecti->base.accel_ceased = ecm_front_end_ipv4_connection_tcp_front_end_accel_ceased;
	fecti->base.xml_state_get = ecm_front_end_ipv4_connection_tcp_front_end_xml_state_get;

	return fecti;
}

/*
 * ecm_front_end_ipv4_connection_udp_callback()
 *	Callback for handling create ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_udp_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_create_msg *__attribute__((unused))nircm = &nim->msg.rule_create;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_udp_instance *fecui;

	/*
	 * Is this a response to a create message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_CREATE_RULE_MSG) {
		DEBUG_ERROR("%p: udp create callback with improper type: %d, serial: %u\n", nim, nim->cm.type, serial);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: create callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: accelerate response for connection: %p, serial: %u\n", fecui, fecui->ci, serial);
	DEBUG_TRACE("%p: rule_flags: %x, valid_flags: %x\n", fecui, nircm->rule_flags, nircm->valid_flags);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecui, &nircm->tuple.flow_ip, nircm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecui, &nircm->tuple.return_ip, nircm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecui, nircm->tuple.protocol);

	/*
	 * Handle the creation result code.
	 */
	DEBUG_TRACE("%p: response: %d\n", fecui, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		/*
		 * Creation command failed (specific reason ignored).
		 */
		DEBUG_TRACE("%p: accel nack: %d\n", fecui, nim->cm.error);
		spin_lock_bh(&fecui->lock);
		DEBUG_ASSERT(fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecui->accel_mode);
		fecui->base.stats.nss_nack++;
		fecui->base.stats.nss_nack_total++;
		if (fecui->base.stats.nss_nack >= fecui->base.stats.nss_nack_limit) {
			/*
			 * Too many NSS rejections
			 */
			fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NSS;
		} else {
			/*
			 * Revert to decelerated
			 */
			fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		}

		/*
		 * Clear any decelerate pending flag since we aren't accelerated anyway we can just clear this whether it is set or not
		 */
		fecui->base.stats.decelerate_pending = false;

		/*
		 * If connection is now defunct then set mode to ensure no further accel attempts occur
		 */
		if (fecui->is_defunct) {
			fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		}
		spin_unlock_bh(&fecui->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	spin_lock_bh(&fecui->lock);
	DEBUG_ASSERT(fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecui->accel_mode);

	/*
	 * If a flush occured before we got the ACK then our acceleration was effectively cancelled on us
	 * GGG TODO This is a workaround for a NSS message OOO quirk, this should eventually be removed.
	 */
	if (fecui->base.stats.flush_happened) {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		fecui->base.stats.flush_happened = false;

		/*
		 * We are decelerated, clear any pending flag as that is meaningless now.
		 */
		fecui->base.stats.decelerate_pending = false;

		/*
		 * Increement the no-action counter.  Our connectin was decelerated on us with no action occurring.
		 */
		fecui->base.stats.no_action_seen++;
		spin_unlock_bh(&fecui->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	/*
	 * We got an ACK - we are accelerated.
	 */
	fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL;

	/*
	 * Create succeeded, declare that we are accelerated.
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_udp_accelerated_count++;	/* Protocol specific counter */
	ecm_front_end_ipv4_accelerated_count++;		/* General running counter */
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Clear any nack count
	 */
	fecui->base.stats.nss_nack = 0;

	/*
	 * Decelerate may have been attempted while we were accel pending.
	 * If decelerate is pending then we need to begin deceleration :-(
	 */
	if (!fecui->base.stats.decelerate_pending) {
		/*
		 * Increement the no-action counter, this is reset if offload action is seen
		 */
		fecui->base.stats.no_action_seen++;

		spin_unlock_bh(&fecui->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_INFO("%p: Decelerate was pending\n", ci);
	fecui->base.stats.decelerate_pending = false;
	spin_unlock_bh(&fecui->lock);

	feci->decelerate(feci);

	/*
	 * Release the connection.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accelerate()
 *	Accelerate a connection
 *
 * GGG TODO Refactor this function into a single function that np, udp and tcp
 * can all use and reduce the amount of code!
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	ip_addr_t addr;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_create_msg *nircm;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;
	uint8_t dest_mac_xlate[ETH_ALEN];
	ecm_db_direction_t ecm_dir;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecui, fecui->ci);
	spin_lock_bh(&fecui->lock);
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecui->accel_mode)) {
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: accel %p failed\n", fecui, fecui->ci);
		return;
	}

	/*
	 * If acceleration mode is anything other than "not accelerated" then ignore.
	 */
	if (fecui->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: Ignoring wrong mode accel for conn: %p\n", fecui, fecui->ci);
		return;
	}
	fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING;
	spin_unlock_bh(&fecui->lock);

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure.
	 * NOTE: We leverage the app_data void pointer to be our 32 bit connection serial number.
	 * When we get it back we re-cast it to a uint32 and do a faster connection lookup.
	 */
	memset(&nim, 0, sizeof(struct nss_ipv4_msg));
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_CREATE_RULE_MSG,
			sizeof(struct nss_ipv4_rule_create_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_udp_callback,
			(void *)ecm_db_connection_serial_get(fecui->ci));

	nircm = &nim.msg.rule_create;
	nircm->valid_flags = 0;
	nircm->rule_flags = 0;

	/*
	 * Initialize VLAN tag information
	 */
	nircm->vlan_primary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_primary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection, we must have at least one interface in the list to continue
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecui->ci, from_ifaces);
	if (from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in from_interfaces list!\n", fecui);
		goto udp_accel_bad_rule;
	}

	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecui->ci, to_ifaces);
	if (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in to_interfaces list!\n", fecui);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		goto udp_accel_bad_rule;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecui, from_nss_iface_id, to_nss_iface_id);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto udp_accel_bad_rule;
	}

	/*
	 * New rule being created
	 */
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	nircm->conn_rule.flow_interface_num = from_nss_iface_id;
	nircm->conn_rule.return_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecui);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecui, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_in_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecui);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecui, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecui);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecui, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecui);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);

			nircm->pppoe_rule.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecui,
					nircm->pppoe_rule.flow_pppoe_session_id,
					nircm->pppoe_rule.flow_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			DEBUG_TRACE("%p: VLAN\n", fecui);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecui);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_in_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_in_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_in_dev, pr->return_qos_tag);
				dev_put(vlan_in_dev);
				vlan_in_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.ingress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.ingress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecui, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecui, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecui);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecui);
				break;
			}
			nircm->conn_rule.flow_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecui, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecui);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto udp_accel_bad_rule;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecui);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecui, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_out_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecui);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecui, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecui);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecui, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecui);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			nircm->pppoe_rule.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecui,
				    nircm->pppoe_rule.return_pppoe_session_id,
				    nircm->pppoe_rule.return_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			DEBUG_TRACE("%p: VLAN\n", fecui);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecui);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_out_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_out_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_out_dev, pr->flow_qos_tag);
				dev_put(vlan_out_dev);
				vlan_out_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.egress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.egress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecui, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecui, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecui);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecui);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecui);
				break;
			}
			nircm->conn_rule.return_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecui, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: to/dest Rule invalid\n", fecui);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto udp_accel_bad_rule;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecui->ci)) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	} else {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Set up the flow and return qos tags
	 */
	nircm->qos_rule.flow_qos_tag = (uint32_t)pr->flow_qos_tag;
	nircm->qos_rule.return_qos_tag = (uint32_t)pr->return_qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	/*
	 * DSCP information?
	 */
	if (pr->process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
		nircm->dscp_rule.flow_dscp = pr->flow_dscp;
		nircm->dscp_rule.return_dscp = pr->return_dscp;
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID;
	}

	/*
	 * Set protocol
	 */
	nircm->tuple.protocol = (int32_t)IPPROTO_UDP;

	/*
	 * The flow_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.flow_ip, addr);

	/*
	 * The return_ip is where the connection is established to, however, in the case of ingress
	 * the return_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.return_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.flow_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.return_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	nircm->tuple.flow_ident = ecm_db_connection_from_port_get(fecui->ci);
	nircm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecui->ci);
	nircm->conn_rule.flow_ident_xlate = ecm_db_connection_from_port_nat_get(fecui->ci);
	nircm->conn_rule.return_ident_xlate = ecm_db_connection_to_port_get(fecui->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecui->ci, (uint8_t *)nircm->conn_rule.flow_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecui->ci, (uint8_t *)nircm->conn_rule.return_mac);

	/*
	 * The dest_mac_xlate is the mac address to replace the pkt.dst_mac when a packet is sent to->from
	 * For bridged connections this does not change.
	 * For routed connections this is the mac of the 'to' node side of the connection.
	 */
	if (ecm_db_connection_is_routed_get(fecui->ci)) {
		ecm_db_connection_to_node_address_get(fecui->ci, dest_mac_xlate);
	} else {
		/*
		 * Bridge flows preserve the MAC addressing
		 */
		memcpy(dest_mac_xlate, (uint8_t *)nircm->conn_rule.return_mac, ETH_ALEN);
	}

	/*
	 * Refer to the Example 2 and 3 in ecm_front_end_ipv4_ip_process() function for egress
	 * and ingress NAT'ed cases. In these cases, the destination node is the one which has the
	 * ip_dest_addr. So, above we get the mac address of this host and use that mac address
	 * for the destination node address in NAT'ed cases.
	 */
	ecm_dir = ecm_db_connection_direction_get(fecui->ci);
	if ((ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT)) {
		memcpy(nircm->conn_rule.return_mac, dest_mac_xlate, ETH_ALEN);
	}

	/*
	 * Get MTU information
	 */
	nircm->conn_rule.flow_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecui->ci);
	nircm->conn_rule.return_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecui->ci);

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecui->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecui, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, nircm);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: UDP Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"ingress_inner_vlan_tag: %u\n"
			"egress_inner_vlan_tag: %u\n"
			"ingress_outer_vlan_tag: %u\n"
			"egress_outer_vlan_tag: %u\n"
			"rule_flags: %x\n"
			"valid_flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"flow_qos_tag: %x (%u)\n"
			"return_qos_tag: %x (%u)\n"
			"flow_dscp: %x\n"
			"return_dscp: %x\n",
			fecui,
			fecui->ci,
			nircm->tuple.protocol,
			nircm->conn_rule.flow_mtu,
			nircm->conn_rule.return_mtu,
			&nircm->tuple.flow_ip, nircm->tuple.flow_ident,
			&nircm->tuple.return_ip, nircm->tuple.return_ident,
			&nircm->conn_rule.flow_ip_xlate, nircm->conn_rule.flow_ident_xlate,
			&nircm->conn_rule.return_ip_xlate, nircm->conn_rule.return_ident_xlate,
			nircm->conn_rule.flow_mac,
			nircm->conn_rule.return_mac,
			nircm->conn_rule.flow_interface_num,
			nircm->conn_rule.return_interface_num,
			nircm->vlan_primary_rule.ingress_vlan_tag,
			nircm->vlan_primary_rule.egress_vlan_tag,
			nircm->vlan_secondary_rule.ingress_vlan_tag,
			nircm->vlan_secondary_rule.egress_vlan_tag,
			nircm->rule_flags,
			nircm->valid_flags,
			nircm->pppoe_rule.return_pppoe_session_id,
			nircm->pppoe_rule.return_pppoe_remote_mac,
			nircm->pppoe_rule.flow_pppoe_session_id,
			nircm->pppoe_rule.flow_pppoe_remote_mac,
			nircm->qos_rule.flow_qos_tag, nircm->qos_rule.flow_qos_tag,
			nircm->qos_rule.return_qos_tag, nircm->qos_rule.return_qos_tag,
			nircm->dscp_rule.flow_dscp,
			nircm->dscp_rule.return_dscp);

	/*
	 * Ref the connection before issuing an NSS rule
	 * This ensures that when the NSS responds to the command - which may even be immediately -
	 * the callback function can trust the correct ref was taken for its purpose.
	 * NOTE: remember that this will also implicitly hold the feci.
	 */
	ecm_db_connection_ref(fecui->ci);

	/*
	 * Call the rule create function
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecui->lock);
		//DEBUG_ASSERT(fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecui, fecui->accel_mode);
		fecui->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * Release that ref!
	 */
	ecm_db_connection_deref(fecui->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecui->lock);
	//DEBUG_ASSERT(fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecui, fecui->accel_mode);
	fecui->base.stats.driver_fail_total++;
	fecui->base.stats.driver_fail++;
	if (fecui->base.stats.driver_fail >= fecui->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Accel failed - driver fail limit\n", fecui);
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecui->lock);
	return;

udp_accel_bad_rule:
	;

	/*
	 * Jump to here when rule data is bad and an offload command cannot be constructed
	 */
	DEBUG_WARN("%p: Accel failed - bad rule\n", fecui);
	spin_lock_bh(&fecui->lock);
	DEBUG_ASSERT(fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecui, fecui->accel_mode);
	fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_RULE;
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_destroy_callback()
 *	Callback for handling destroy ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_udp_destroy_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_destroy_msg *__attribute__((unused))nirdm = &nim->msg.rule_destroy;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_udp_instance *fecui;

	/*
	 * Is this a response to a destroy message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_DESTROY_RULE_MSG) {
		DEBUG_ERROR("%p: udp destroy callback with improper type: %d\n", nim, nim->cm.type);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: destroy callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: decelerate response for connection: %p\n", fecui, fecui->ci);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecui, &nirdm->tuple.flow_ip, nirdm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecui, &nirdm->tuple.return_ip, nirdm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecui, nirdm->tuple.protocol);

	spin_lock_bh(&fecui->lock);

	/*
	 * If decel is not still pending then it's possible that the NSS ended acceleration by some other reason e.g. flush
	 * In which case we cannot rely on the response we get here.
	 */
	if (fecui->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecui->lock);

		/*
		 * Release the connections.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_TRACE("%p: response: %d\n", fecui, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DECEL;
	} else {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}

	/*
	 * If connection became defunct then set mode so that no further accel/decel attempts occur.
	 */
	if (fecui->is_defunct) {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
	}
	spin_unlock_bh(&fecui->lock);

	/*
	 * UDP acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_udp_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_udp_accelerated_count >= 0, "Bad udp accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Release the connections.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_udp_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_destroy_msg *nirdm;
	ip_addr_t addr;
	nss_tx_status_t nss_tx_status;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	/*
	 * If decelerate is in error or already pending then ignore
	 */
	spin_lock_bh(&fecui->lock);
	if (fecui->base.stats.decelerate_pending) {
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If acceleration is pending then we cannot decelerate right now or we will race with it
	 * Set a decelerate pending flag that will be actioned when the acceleration command is complete.
	 */
	if (fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecui->base.stats.decelerate_pending = true;
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * Can only decelerate if accelerated
	 * NOTE: This will also deny accel when the connection is in fail condition too.
	 */
	if (fecui->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * Initiate deceleration
	 */
	fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING;
	spin_unlock_bh(&fecui->lock);

	/*
	 * Prepare deceleration message
	 */
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_DESTROY_RULE_MSG,
			sizeof(struct nss_ipv4_rule_destroy_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_udp_destroy_callback,
			(void *)ecm_db_connection_serial_get(fecui->ci));

	nirdm = &nim.msg.rule_destroy;
	nirdm->tuple.protocol = (int32_t)IPPROTO_UDP;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.flow_ip, addr);
	ecm_db_connection_to_address_nat_get(fecui->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.return_ip, addr);
	nirdm->tuple.flow_ident = ecm_db_connection_from_port_get(fecui->ci);
	nirdm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecui->ci);

	DEBUG_INFO("%p: UDP Connection %p decelerate\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecui, fecui->ci,
			&nirdm->tuple.flow_ip, nirdm->tuple.flow_ident,
			&nirdm->tuple.return_ip, nirdm->tuple.return_ident);

	/*
	 * Take a ref to the feci->ci so that it will persist until we get a response from the NSS.
	 * NOTE: This will implicitly hold the feci too.
	 */
	ecm_db_connection_ref(fecui->ci);

	/*
	 * Destroy the NSS connection cache entry.
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecui->lock);
		fecui->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * Release the ref take, NSS driver did not accept our command.
	 */
	ecm_db_connection_deref(fecui->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecui->lock);
	fecui->base.stats.driver_fail_total++;
	fecui->base.stats.driver_fail++;
	if (fecui->base.stats.driver_fail >= fecui->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Decel failed - driver fail limit\n", fecui);
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_defunct_callback()
 *	Callback to be called when a UDP connection has become defunct.
 */
static void ecm_front_end_ipv4_connection_udp_defunct_callback(void *arg)
{
	struct ecm_front_end_connection_instance *feci = (struct ecm_front_end_connection_instance *)arg;
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	spin_lock_bh(&fecui->lock);

	/*
	 * If connection has already become defunct, do nothing.
	 */
	if (fecui->is_defunct) {
		spin_unlock_bh(&fecui->lock);
		return;
	}
	fecui->is_defunct = true;

	/*
	 * If the connection is already in one of the fail modes, do nothing, keep the current accel_mode.
	 */
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecui->accel_mode)) {
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If the connection is decel then ensure it will not attempt accel while defunct.
	 */
	if (fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If the connection is decel pending then decel operation is in progress anyway.
	 */
	if (fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If none of the cases mathes above, this means the connection is in one of the
	 * accel modes (accel or accel_pending) so we force a deceleration.
	 * NOTE: If the mode is accel pending then the decel will be actioned when that is completed.
	 */
	spin_unlock_bh(&fecui->lock);
	ecm_front_end_ipv4_connection_udp_front_end_decelerate(feci);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accel_state_get()
 *	Get acceleration state
 */
static ecm_front_end_acceleration_mode_t ecm_front_end_ipv4_connection_udp_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;
	ecm_front_end_acceleration_mode_t state;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	spin_lock_bh(&fecui->lock);
	state = fecui->accel_mode;
	spin_unlock_bh(&fecui->lock);
	return state;
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_action_seen()
 *	Acceleration action / activity has been seen for this connection.
 *
 * NOTE: Call the action_seen() method when the NSS has demonstrated that it has offloaded some data for a connection.
 */
static void ecm_front_end_ipv4_connection_udp_front_end_action_seen(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	DEBUG_INFO("%p: Action seen\n", fecui);
	spin_lock_bh(&fecui->lock);
	fecui->base.stats.no_action_seen = 0;
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_accel_ceased()
 *	NSS has indicated that acceleration has stopped.
 *
 * NOTE: This is called in response to an NSS self-initiated termination of acceleration.
 * This must NOT be called because the ECM terminated the acceleration.
 */
static void ecm_front_end_ipv4_connection_udp_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	DEBUG_INFO("%p: accel ceased\n", fecui);

	spin_lock_bh(&fecui->lock);

	/*
	 * If we are in accel-pending state then the NSS has issued a flush out-of-order
	 * with the ACK/NACK we are actually waiting for.
	 * To work around this we record a "flush has already happened" and will action it when we finally get that ACK/NACK.
	 * GGG TODO This should eventually be removed when the NSS honours messaging sequence.
	 */
	if (fecui->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecui->base.stats.flush_happened = true;
		fecui->base.stats.flush_happened_total++;
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If connection is no longer accelerated by the time we get here just ignore the command
	 */
	if (fecui->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecui->lock);
		return;
	}

	/*
	 * If the no_action_seen counter was not reset then acceleration ended without any offload action
	 */
	if (fecui->base.stats.no_action_seen) {
		fecui->base.stats.no_action_seen_total++;
	}

	/*
	 * If the no_action_seen indicates successive cessations of acceleration without any offload action occuring
	 * then we fail out this connection
	 */
	if (fecui->base.stats.no_action_seen >= fecui->base.stats.no_action_seen_limit) {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NO_ACTION;
	} else {
		fecui->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}
	spin_unlock_bh(&fecui->lock);

	/*
	 * UDP acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_udp_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_udp_accelerated_count >= 0, "Bad udp accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_udp_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);
	spin_lock_bh(&fecui->lock);
	fecui->refs++;
	DEBUG_TRACE("%p: fecui ref %d\n", fecui, fecui->refs);
	DEBUG_ASSERT(fecui->refs > 0, "%p: ref wrap\n", fecui);
	spin_unlock_bh(&fecui->lock);
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_udp_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	spin_lock_bh(&fecui->lock);
	fecui->refs--;
	DEBUG_ASSERT(fecui->refs >= 0, "%p: ref wrap\n", fecui);

	if (fecui->refs > 0) {
		int refs = fecui->refs;
		spin_unlock_bh(&fecui->lock);
		DEBUG_TRACE("%p: fecui deref %d\n", fecui, refs);
		return refs;
	}
	spin_unlock_bh(&fecui->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecui final\n", fecui);
	DEBUG_CLEAR_MAGIC(fecui);
	kfree(fecui);

	/*
	 * Thread may be able to exit on object destruction
	 */
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_udp_front_end_xml_state_get()
 *	Return an XML element containing the state of this UDP front end instance
 */
static int ecm_front_end_ipv4_connection_udp_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_front_end_acceleration_mode_t accel_mode;
	struct ecm_front_end_connection_mode_stats stats;
	struct ecm_front_end_ipv4_connection_udp_instance *fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)feci;

	DEBUG_CHECK_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC, "%p: magic failed", fecui);

	spin_lock_bh(&fecui->lock);
	can_accel = fecui->can_accel;
	accel_mode = fecui->accel_mode;
	memcpy(&stats, &feci->stats, sizeof(struct ecm_front_end_connection_mode_stats));
	spin_unlock_bh(&fecui->lock);

	return snprintf(buf, buf_sz, "<front_end_udp can_accel=\"%d\" accel_mode=\"%d\" decelerate_pending=\"%d\" flush_happened_total=\"%d\" no_action_seen_total=\"%d\" no_action_seen=\"%d\" no_action_seen_limit=\"%d\""
				" driver_fail_total=\"%d\" driver_fail=\"%d\" driver_fail_limit=\"%d\" nss_nack_total=\"%d\" nss_nack=\"%d\" nss_nack_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			stats.decelerate_pending,
			stats.flush_happened_total,
			stats.no_action_seen_total,
			stats.no_action_seen,
			stats.no_action_seen_limit,
			stats.driver_fail_total,
			stats.driver_fail,
			stats.driver_fail_limit,
			stats.nss_nack_total,
			stats.nss_nack,
			stats.nss_nack_limit);

}

/*
 * ecm_front_end_ipv4_connection_udp_instance_alloc()
 *	Create a front end instance specific for UDP connection
 */
static struct ecm_front_end_ipv4_connection_udp_instance *ecm_front_end_ipv4_connection_udp_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi,
								bool can_accel)
{
	struct ecm_front_end_ipv4_connection_udp_instance *fecui;

	fecui = (struct ecm_front_end_ipv4_connection_udp_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_udp_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecui) {
		DEBUG_WARN("UDP Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecui->refs = 1;
	DEBUG_SET_MAGIC(fecui, ECM_FRONT_END_IPV4_CONNECTION_UDP_INSTANCE_MAGIC);
	spin_lock_init(&fecui->lock);

	fecui->can_accel = can_accel;
	fecui->accel_mode = (can_accel)? ECM_FRONT_END_ACCELERATION_MODE_DECEL : ECM_FRONT_END_ACCELERATION_MODE_FAIL_DENIED;
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	fecui->base.stats.no_action_seen_limit = ecm_front_end_ipv4_no_action_limit_default;
	fecui->base.stats.driver_fail_limit = ecm_front_end_ipv4_driver_fail_limit_default;
	fecui->base.stats.nss_nack_limit = ecm_front_end_ipv4_nack_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecui->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecui->base.ref = ecm_front_end_ipv4_connection_udp_front_end_ref;
	fecui->base.deref = ecm_front_end_ipv4_connection_udp_front_end_deref;
	fecui->base.decelerate = ecm_front_end_ipv4_connection_udp_front_end_decelerate;
	fecui->base.accel_state_get = ecm_front_end_ipv4_connection_udp_front_end_accel_state_get;
	fecui->base.action_seen = ecm_front_end_ipv4_connection_udp_front_end_action_seen;
	fecui->base.accel_ceased = ecm_front_end_ipv4_connection_udp_front_end_accel_ceased;
	fecui->base.xml_state_get = ecm_front_end_ipv4_connection_udp_front_end_xml_state_get;

	return fecui;
}

#ifdef CONFIG_IPV6_SIT_6RD
#ifdef ECM_INTERFACE_SIT_ENABLE
/*
 * ecm_front_end_ipv4_sit_set_peer()
 *	It will set the tunnel's peer when the tunnel is a remote any tunnel.
 */
static void ecm_front_end_ipv4_sit_set_peer(struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi, struct sk_buff *skb)
{
	struct nss_tun6rd_msg tun6rdmsg;
	struct nss_tun6rd_set_peer_msg *tun6rdpeer;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	int32_t from_ifaces_first;
	const struct ipv6hdr *iph6;
	uint16_t interface_number;
	ecm_db_iface_type_t ii_type;
	ip_addr_t addr;
	nss_tx_status_t nss_tx_status;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecnpi->ci, from_ifaces);
	if (from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in from_interfaces list!\n", fecnpi);
		return;
	}

	from_nss_iface = from_ifaces[from_ifaces_first];
	ii_type = ecm_db_connection_iface_type_get(from_nss_iface);

	/*
	 * We handle SIT tunnel only here
	 */
	if (ii_type != ECM_DB_IFACE_TYPE_SIT) {
		DEBUG_WARN("%p: This interface is not the sit tunnel\n", fecnpi);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		return;
	}

	/*
	 * We catch these packets in the tunnel which destination ip address is null
	 */
	if (!ecm_db_iface_sit_daddr_is_null(from_nss_iface)) {
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		return;
	}
	ecm_db_connection_to_address_get(fecnpi->ci, addr);

	interface_number = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	nss_tun6rd_msg_init(&tun6rdmsg, interface_number, NSS_TUN6RD_ADD_UPDATE_PEER,
			sizeof(struct nss_tun6rd_set_peer_msg), NULL, NULL);

	tun6rdpeer = &tun6rdmsg.msg.peer;
	ECM_IP_ADDR_TO_NIN4_ADDR(tun6rdpeer->dest, addr);
	iph6 = (struct ipv6hdr *)skb_transport_header(skb);
	memcpy(tun6rdpeer->ipv6_address,&iph6->daddr, sizeof(struct  in6_addr));

	nss_tx_status = nss_tun6rd_tx(nss_tun6rd_get_context(), &tun6rdmsg);
	if (nss_tx_status != NSS_TX_SUCCESS) {
		/*
		 * Nothing to do when faild to xmit the message.
		 */
		DEBUG_WARN("SIT Accelerate set rule failed\n");
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		return;
	}
	DEBUG_TRACE("%p: SIT[%d] set peer\n"
		   "ipv4 destination address:%x\n"
		   "ipv6 destination address::"ECM_IP_ADDR_OCTAL_FMT"\n",
		fecnpi, interface_number, tun6rdpeer->dest, ECM_IP_ADDR_TO_OCTAL(tun6rdpeer->ipv6_address));

	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
}
#endif
#endif

/*
 * ecm_front_end_ipv4_connection_non_ported_callback()
 *	Callback for handling create ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_non_ported_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_create_msg *__attribute__((unused))nircm = &nim->msg.rule_create;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi;

	/*
	 * Is this a response to a create message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_CREATE_RULE_MSG) {
		DEBUG_ERROR("%p: non_ported create callback with improper type: %d, serial: %u\n", nim, nim->cm.type, serial);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: create callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: accelerate response for connection: %p, serial: %u\n", fecnpi, fecnpi->ci, serial);
	DEBUG_TRACE("%p: rule_flags: %x, valid_flags: %x\n", fecnpi, nircm->rule_flags, nircm->valid_flags);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecnpi, &nircm->tuple.flow_ip, nircm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecnpi, &nircm->tuple.return_ip, nircm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecnpi, nircm->tuple.protocol);

	/*
	 * Handle the creation result code.
	 */
	DEBUG_TRACE("%p: response: %d\n", fecnpi, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		/*
		 * Creation command failed (specific reason ignored).
		 */
		DEBUG_TRACE("%p: accel nack: %d\n", fecnpi, nim->cm.error);
		spin_lock_bh(&fecnpi->lock);
		DEBUG_ASSERT(fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecnpi->accel_mode);
		fecnpi->base.stats.nss_nack++;
		fecnpi->base.stats.nss_nack_total++;
		if (fecnpi->base.stats.nss_nack >= fecnpi->base.stats.nss_nack_limit) {
			/*
			 * Too many NSS rejections
			 */
			fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NSS;
		} else {
			/*
			 * Revert to decelerated
			 */
			fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		}

		/*
		 * Clear any decelerate pending flag since we aren't accelerated anyway we can just clear this whether it is set or not
		 */
		fecnpi->base.stats.decelerate_pending = false;

		/*
		 * If connection is now defunct then set mode to ensure no further accel attempts occur
		 */
		if (fecnpi->is_defunct) {
			fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		}
		spin_unlock_bh(&fecnpi->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	spin_lock_bh(&fecnpi->lock);
	DEBUG_ASSERT(fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Unexpected mode: %d\n", ci, fecnpi->accel_mode);

	/*
	 * If a flush occured before we got the ACK then our acceleration was effectively cancelled on us
	 * GGG TODO This is a workaround for a NSS message OOO quirk, this should eventually be removed.
	 */
	if (fecnpi->base.stats.flush_happened) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
		fecnpi->base.stats.flush_happened = false;

		/*
		 * We are decelerated, clear any pending flag as that is meaningless now.
		 */
		fecnpi->base.stats.decelerate_pending = false;

		/*
		 * Increement the no-action counter.  Our connectin was decelerated on us with no action occurring.
		 */
		fecnpi->base.stats.no_action_seen++;
		spin_unlock_bh(&fecnpi->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	/*
	 * We got an ACK - we are accelerated.
	 */
	fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL;

	/*
	 * Create succeeded, declare that we are accelerated.
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_non_ported_accelerated_count++;	/* Protocol specific counter */
	ecm_front_end_ipv4_accelerated_count++;			/* General running counter */
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Clear any nack count
	 */
	fecnpi->base.stats.nss_nack = 0;

	/*
	 * Decelerate may have been attempted while we were accel pending.
	 * If decelerate is pending then we need to begin deceleration :-(
	 */
	if (!fecnpi->base.stats.decelerate_pending) {
		/*
		 * Increement the no-action counter, this is reset if offload action is seen
		 */
		fecnpi->base.stats.no_action_seen++;

		spin_unlock_bh(&fecnpi->lock);

		/*
		 * Release the connection.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_INFO("%p: Decelerate was pending\n", ci);
	fecnpi->base.stats.decelerate_pending = false;
	spin_unlock_bh(&fecnpi->lock);

	feci->decelerate(feci);

	/*
	 * Release the connection.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accelerate()
 *	Accelerate a connection
 *
 * GGG TODO Refactor this function into a single function that np, udp and tcp
 * can all use and reduce the amount of code!
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accelerate(struct ecm_front_end_connection_instance *feci,
									struct ecm_classifier_process_response *pr)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	int protocol;
	int32_t from_ifaces_first;
	int32_t to_ifaces_first;
	struct ecm_db_iface_instance *from_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *to_ifaces[ECM_DB_IFACE_HEIRARCHY_MAX];
	struct ecm_db_iface_instance *from_nss_iface;
	struct ecm_db_iface_instance *to_nss_iface;
	int32_t from_nss_iface_id;
	int32_t to_nss_iface_id;
	uint8_t from_nss_iface_address[ETH_ALEN];
	uint8_t to_nss_iface_address[ETH_ALEN];
	ip_addr_t addr;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_create_msg *nircm;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	nss_tx_status_t nss_tx_status;
	int32_t list_index;
	int32_t interface_type_counts[ECM_DB_IFACE_TYPE_COUNT];
	bool rule_invalid;
	uint8_t dest_mac_xlate[ETH_ALEN];
	ecm_db_direction_t ecm_dir;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * Get connection protocol
	 */
	protocol = ecm_db_connection_protocol_get(fecnpi->ci);

	/*
	 * Can this connection be accelerated at all?
	 */
	DEBUG_INFO("%p: Accel conn: %p\n", fecnpi, fecnpi->ci);
	spin_lock_bh(&fecnpi->lock);
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecnpi->accel_mode)) {
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: accel %p denied\n", fecnpi, fecnpi->ci);
		return;
	}

	/*
	 * For non-ported protocols we only support IPv6 in 4 or ESP
	 */
	if ((protocol != IPPROTO_IPV6) && (protocol != IPPROTO_ESP)) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_RULE;
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: unsupported protocol: %d\n", fecnpi, protocol);
		return;
	}

	/*
	 * If acceleration mode is anything other than "not accelerated" then ignore.
	 */
	if (fecnpi->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: Ignoring wrong mode accel for conn: %p\n", fecnpi, fecnpi->ci);
		return;
	}
	fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING;
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * Okay construct an accel command.
	 * Initialise creation structure.
	 * NOTE: We leverage the app_data void pointer to be our 32 bit connection serial number.
	 * When we get it back we re-cast it to a uint32 and do a faster connection lookup.
	 */
	memset(&nim, 0, sizeof(struct nss_ipv4_msg));
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_CREATE_RULE_MSG,
			sizeof(struct nss_ipv4_rule_create_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_non_ported_callback,
			(void *)ecm_db_connection_serial_get(fecnpi->ci));

	nircm = &nim.msg.rule_create;
	nircm->valid_flags = 0;
	nircm->rule_flags = 0;

	/*
	 * Initialize VLAN tag information
	 */
	nircm->vlan_primary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_primary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.ingress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;
	nircm->vlan_secondary_rule.egress_vlan_tag = ECM_NSS_CONNMGR_VLAN_ID_NOT_CONFIGURED;

	/*
	 * Get the interface lists of the connection, we must have at least one interface in the list to continue
	 */
	from_ifaces_first = ecm_db_connection_from_interfaces_get_and_ref(fecnpi->ci, from_ifaces);
	if (from_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in from_interfaces list!\n", fecnpi);
		goto non_ported_accel_bad_rule;
	}

	to_ifaces_first = ecm_db_connection_to_interfaces_get_and_ref(fecnpi->ci, to_ifaces);
	if (to_ifaces_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		DEBUG_WARN("%p: Accel attempt failed - no interfaces in to_interfaces list!\n", fecnpi);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		goto non_ported_accel_bad_rule;
	}

	/*
	 * First interface in each must be a known nss interface
	 */
	from_nss_iface = from_ifaces[from_ifaces_first];
	to_nss_iface = to_ifaces[to_ifaces_first];
	from_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(from_nss_iface);
	to_nss_iface_id = ecm_db_iface_nss_interface_identifier_get(to_nss_iface);
	if ((from_nss_iface_id < 0) || (to_nss_iface_id < 0)) {
		DEBUG_TRACE("%p: from_nss_iface_id: %d, to_nss_iface_id: %d\n", fecnpi, from_nss_iface_id, to_nss_iface_id);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto non_ported_accel_bad_rule;
	}

	/*
	 * New rule being created
	 */
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	/*
	 * Set interface numbers involved in accelerating this connection.
	 * These are the outer facing addresses from the heirarchy interface lists we got above.
	 * These may be overridden later if we detect special interface types e.g. ipsec.
	 */
	nircm->conn_rule.flow_interface_num = from_nss_iface_id;
	nircm->conn_rule.return_interface_num = to_nss_iface_id;

	/*
	 * We know that each outward facing interface is known to the NSS and so this connection could be accelerated.
	 * However the lists may also specify other interesting details that must be included in the creation command,
	 * for example, ethernet MAC, VLAN tagging or PPPoE session information.
	 * We get this information by walking from the outer to the innermost interface for each list and examine the interface types.
	 *
	 * Start with the 'from' (src) side.
	 * NOTE: The lists may contain a complex heirarchy of similar type of interface e.g. multiple vlans or tunnels within tunnels.
	 * This NSS cannot handle that - there is no way to describe this in the rule - if we see multiple types that would conflict we have to abort.
	 */
	DEBUG_TRACE("%p: Examine from/src heirarchy list\n", fecnpi);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = from_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = from_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecnpi, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_in_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecnpi);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecnpi, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecnpi);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, from_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecnpi, from_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecnpi);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);

			nircm->pppoe_rule.flow_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.flow_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecnpi,
					nircm->pppoe_rule.flow_pppoe_session_id,
					nircm->pppoe_rule.flow_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
		case ECM_DB_IFACE_TYPE_VLAN:
#ifdef ECM_INTERFACE_VLAN_ENABLE
			DEBUG_TRACE("%p: VLAN\n", fecnpi);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecnpi);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_in_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_in_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_in_dev, pr->return_qos_tag);
				dev_put(vlan_in_dev);
				vlan_in_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.ingress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.ingress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(from_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecnpi, from_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecnpi, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecnpi);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecnpi);
				break;
			}
			nircm->conn_rule.flow_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecnpi, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: from/src Rule invalid\n", fecnpi);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto non_ported_accel_bad_rule;
	}

	/*
	 * Now examine the TO / DEST heirarchy list to construct the destination part of the rule
	 */
	DEBUG_TRACE("%p: Examine to/dest heirarchy list\n", fecnpi);
	memset(interface_type_counts, 0, sizeof(interface_type_counts));
	rule_invalid = false;
	for (list_index = to_ifaces_first; !rule_invalid && (list_index < ECM_DB_IFACE_HEIRARCHY_MAX); list_index++) {
		struct ecm_db_iface_instance *ii;
		ecm_db_iface_type_t ii_type;
		char *ii_name;

		ii = to_ifaces[list_index];
		ii_type = ecm_db_connection_iface_type_get(ii);
		ii_name = ecm_db_interface_type_to_string(ii_type);
		DEBUG_TRACE("%p: list_index: %d, ii: %p, type: %d (%s)\n", fecnpi, list_index, ii, ii_type, ii_name);

		/*
		 * Extract information from this interface type if it is applicable to the rule.
		 * Conflicting information may cause accel to be unsupported.
		 */
		switch (ii_type) {
#ifdef ECM_INTERFACE_PPP_ENABLE
			struct ecm_db_interface_info_pppoe pppoe_info;
#endif
#ifdef ECM_INTERFACE_VLAN_ENABLE
			struct ecm_db_interface_info_vlan vlan_info;
			uint32_t vlan_value = 0;
			struct net_device *vlan_out_dev = NULL;
#endif

		case ECM_DB_IFACE_TYPE_BRIDGE:
			DEBUG_TRACE("%p: Bridge\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Cannot cascade bridges
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: Bridge - ignore additional\n", fecnpi);
				break;
			}
			ecm_db_iface_bridge_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Bridge - mac: %pM\n", fecnpi, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_ETHERNET:
			DEBUG_TRACE("%p: Ethernet\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Ignore additional mac addresses, these are usually as a result of address propagation
				 * from bridges down to ports etc.
				 */
				DEBUG_TRACE("%p: Ethernet - ignore additional\n", fecnpi);
				break;
			}

			/*
			 * Can only handle one MAC, the first outermost mac.
			 */
			ecm_db_iface_ethernet_address_get(ii, to_nss_iface_address);
			DEBUG_TRACE("%p: Ethernet - mac: %pM\n", fecnpi, to_nss_iface_address);
			break;
		case ECM_DB_IFACE_TYPE_PPPOE:
#ifdef ECM_INTERFACE_PPP_ENABLE
			/*
			 * More than one PPPoE in the list is not valid!
			 */
			if (interface_type_counts[ii_type] != 0) {
				DEBUG_TRACE("%p: PPPoE - additional unsupported\n", fecnpi);
				rule_invalid = true;
				break;
			}

			/*
			 * Copy pppoe session info to the creation structure.
			 */
			ecm_db_iface_pppoe_session_info_get(ii, &pppoe_info);
			nircm->pppoe_rule.return_pppoe_session_id = pppoe_info.pppoe_session_id;
			memcpy(nircm->pppoe_rule.return_pppoe_remote_mac, pppoe_info.remote_mac, ETH_ALEN);
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_PPPOE_VALID;

			DEBUG_TRACE("%p: PPPoE - session: %x, mac: %pM\n", fecnpi,
				    nircm->pppoe_rule.return_pppoe_session_id,
				    nircm->pppoe_rule.return_pppoe_remote_mac);
#else
			rule_invalid = true;
#endif
			break;
#ifdef ECM_INTERFACE_VLAN_ENABLE
		case ECM_DB_IFACE_TYPE_VLAN:
			DEBUG_TRACE("%p: VLAN\n", fecnpi);
			if (interface_type_counts[ii_type] > 1) {
				/*
				 * Can only support two vlans
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: VLAN - additional unsupported\n", fecnpi);
				break;
			}
			ecm_db_iface_vlan_info_get(ii, &vlan_info);
			vlan_value = ((vlan_info.vlan_tpid << 16) | vlan_info.vlan_tag);

			/*
			 * Look up the vlan device and incorporate the vlan priority into the vlan_value
			 */
			vlan_out_dev = dev_get_by_index(&init_net, ecm_db_iface_interface_identifier_get(ii));
			if (vlan_out_dev) {
				vlan_value |= vlan_dev_get_egress_prio(vlan_out_dev, pr->flow_qos_tag);
				dev_put(vlan_out_dev);
				vlan_out_dev = NULL;
			}

			/*
			 * Primary or secondary (QinQ) VLAN?
			 */
			if (interface_type_counts[ii_type] == 0) {
				nircm->vlan_primary_rule.egress_vlan_tag = vlan_value;
			} else {
				nircm->vlan_secondary_rule.egress_vlan_tag = vlan_value;
			}
			nircm->valid_flags |= NSS_IPV4_RULE_CREATE_VLAN_VALID;

			/*
			 * If we have not yet got an ethernet mac then take this one (very unlikely as mac should have been propagated to the slave (outer) device
			 */
			if (interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET] == 0) {
				memcpy(to_nss_iface_address, vlan_info.address, ETH_ALEN);
				interface_type_counts[ECM_DB_IFACE_TYPE_ETHERNET]++;
				DEBUG_TRACE("%p: VLAN use mac: %pM\n", fecnpi, to_nss_iface_address);
			}
			DEBUG_TRACE("%p: vlan tag: %x\n", fecnpi, vlan_value);
#else
			rule_invalid = true;
			DEBUG_TRACE("%p: VLAN - unsupported\n", fecnpi);
#endif
			break;
		case ECM_DB_IFACE_TYPE_IPSEC_TUNNEL:
			DEBUG_TRACE("%p: IPSEC\n", fecnpi);
			if (interface_type_counts[ii_type] != 0) {
				/*
				 * Can only support one ipsec
				 */
				rule_invalid = true;
				DEBUG_TRACE("%p: IPSEC - additional unsupported\n", fecnpi);
				break;
			}
			nircm->conn_rule.return_interface_num = NSS_C2C_TX_INTERFACE;
			break;
		default:
			DEBUG_TRACE("%p: Ignoring: %d (%s)\n", fecnpi, ii_type, ii_name);
		}

		/*
		 * Seen an interface of this type
		 */
		interface_type_counts[ii_type]++;
	}
	if (rule_invalid) {
		DEBUG_WARN("%p: to/dest Rule invalid\n", fecnpi);
		ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
		ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);
		goto non_ported_accel_bad_rule;
	}

	/*
	 * Routed or bridged?
	 */
	if (ecm_db_connection_is_routed_get(fecnpi->ci)) {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	} else {
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	/*
	 * Set up the flow and return qos tags
	 */
	nircm->qos_rule.flow_qos_tag = (uint32_t)pr->flow_qos_tag;
	nircm->qos_rule.return_qos_tag = (uint32_t)pr->return_qos_tag;
	nircm->valid_flags |= NSS_IPV4_RULE_CREATE_QOS_VALID;

	/*
	 * DSCP information?
	 */
	if (pr->process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
		nircm->dscp_rule.flow_dscp = pr->flow_dscp;
		nircm->dscp_rule.return_dscp = pr->return_dscp;
		nircm->rule_flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
		nircm->valid_flags |= NSS_IPV4_RULE_CREATE_DSCP_MARKING_VALID;
	}

	/*
	 * Set protocol
	 */
	nircm->tuple.protocol = (int32_t)protocol;

	/*
	 * The flow_ip is where the connection established from
	 */
	ecm_db_connection_from_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.flow_ip, addr);

	/*
	 * The return_ip is where the connection is established to, however, in the case of ingress
	 * the return_ip would be the routers WAN IP - i.e. the NAT'ed version.
	 * Getting the NAT'ed version here works for ingress or egress packets, for egress
	 * the NAT'ed version would be the same as the normal address
	 */
	ecm_db_connection_to_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->tuple.return_ip, addr);

	/*
	 * When the packet is forwarded to the next interface get the address the source IP of the
	 * packet should be translated to.  For egress this is the NAT'ed from address.
	 * This also works for ingress as the NAT'ed version of the WAN host would be the same as non-NAT'ed
	 */
	ecm_db_connection_from_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.flow_ip_xlate, addr);

	/*
	 * The destination address is what the destination IP is translated to as it is forwarded to the next interface.
	 * For egress this would yield the normal wan host and for ingress this would correctly NAT back to the LAN host
	 */
	ecm_db_connection_to_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nircm->conn_rule.return_ip_xlate, addr);

	/*
	 * Same approach as above for port information
	 */
	nircm->tuple.flow_ident = ecm_db_connection_from_port_get(fecnpi->ci);
	nircm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecnpi->ci);
	nircm->conn_rule.flow_ident_xlate = ecm_db_connection_from_port_nat_get(fecnpi->ci);
	nircm->conn_rule.return_ident_xlate = ecm_db_connection_to_port_get(fecnpi->ci);

	/*
	 * Get mac addresses.
	 * The src_mac is the mac address of the node that established the connection.
	 * This will work whether the from_node is LAN (egress) or WAN (ingress).
	 */
	ecm_db_connection_from_node_address_get(fecnpi->ci, (uint8_t *)nircm->conn_rule.flow_mac);

	/*
	 * The dest_mac is more complex.  For egress it is the node address of the 'to' side of the connection.
	 * For ingress it is the node adress of the NAT'ed 'to' IP.
	 * Essentially it is the MAC of node associated with create.dest_ip and this is "to nat" side.
	 */
	ecm_db_connection_to_nat_node_address_get(fecnpi->ci, (uint8_t *)nircm->conn_rule.return_mac);

	/*
	 * The dest_mac_xlate is the mac address to replace the pkt.dst_mac when a packet is sent to->from
	 * For bridged connections this does not change.
	 * For routed connections this is the mac of the 'to' node side of the connection.
	 */
	if (ecm_db_connection_is_routed_get(fecnpi->ci)) {
		ecm_db_connection_to_node_address_get(fecnpi->ci, dest_mac_xlate);
	} else {
		/*
		 * Bridge flows preserve the MAC addressing
		 */
		memcpy(dest_mac_xlate, (uint8_t *)nircm->conn_rule.return_mac, ETH_ALEN);
	}

	/*
	 * Refer to the Example 2 and 3 in ecm_front_end_ipv4_ip_process() function for egress
	 * and ingress NAT'ed cases. In these cases, the destination node is the one which has the
	 * ip_dest_addr. So, above we get the mac address of this host and use that mac address
	 * for the destination node address in NAT'ed cases.
	 */
	ecm_dir = ecm_db_connection_direction_get(fecnpi->ci);
	if ((ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT)) {
		memcpy(nircm->conn_rule.return_mac, dest_mac_xlate, ETH_ALEN);
	}

	/*
	 * Get MTU information
	 */
	nircm->conn_rule.flow_mtu = (uint32_t)ecm_db_connection_from_iface_mtu_get(fecnpi->ci);
	nircm->conn_rule.return_mtu = (uint32_t)ecm_db_connection_to_iface_mtu_get(fecnpi->ci);

	/*
	 * Sync our creation command from the assigned classifiers to get specific additional creation rules.
	 * NOTE: These are called in ascending order of priority and so the last classifier (highest) shall
	 * override any preceding classifiers.
	 * This also gives the classifiers a chance to see that acceleration is being attempted.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(fecnpi->ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync from: %p, type: %d\n", fecnpi, aci, aci->type_get(aci));
		aci->sync_from_v4(aci, nircm);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Release the interface lists
	 */
	ecm_db_connection_interfaces_deref(from_ifaces, from_ifaces_first);
	ecm_db_connection_interfaces_deref(to_ifaces, to_ifaces_first);

	DEBUG_INFO("%p: NON PORTED Accelerate connection %p\n"
			"Protocol: %d\n"
			"from_mtu: %u\n"
			"to_mtu: %u\n"
			"from_ip: %pI4h:%d\n"
			"to_ip: %pI4h:%d\n"
			"from_ip_xlate: %pI4h:%d\n"
			"to_ip_xlate: %pI4h:%d\n"
			"from_mac: %pM\n"
			"to_mac: %pM\n"
			"src_iface_num: %u\n"
			"dest_iface_num: %u\n"
			"ingress_inner_vlan_tag: %u\n"
			"egress_inner_vlan_tag: %u\n"
			"ingress_outer_vlan_tag: %u\n"
			"egress_outer_vlan_tag: %u\n"
			"rule_flags: %x\n"
			"valid_flags: %x\n"
			"return_pppoe_session_id: %u\n"
			"return_pppoe_remote_mac: %pM\n"
			"flow_pppoe_session_id: %u\n"
			"flow_pppoe_remote_mac: %pM\n"
			"flow_qos_tag: %x (%u)\n"
			"return_qos_tag: %x (%u)\n"
			"flow_dscp: %x\n"
			"return_dscp: %x\n",
			fecnpi,
			fecnpi->ci,
			nircm->tuple.protocol,
			nircm->conn_rule.flow_mtu,
			nircm->conn_rule.return_mtu,
			&nircm->tuple.flow_ip, nircm->tuple.flow_ident,
			&nircm->tuple.return_ip, nircm->tuple.return_ident,
			&nircm->conn_rule.flow_ip_xlate, nircm->conn_rule.flow_ident_xlate,
			&nircm->conn_rule.return_ip_xlate, nircm->conn_rule.return_ident_xlate,
			nircm->conn_rule.flow_mac,
			nircm->conn_rule.return_mac,
			nircm->conn_rule.flow_interface_num,
			nircm->conn_rule.return_interface_num,
			nircm->vlan_primary_rule.ingress_vlan_tag,
			nircm->vlan_primary_rule.egress_vlan_tag,
			nircm->vlan_secondary_rule.ingress_vlan_tag,
			nircm->vlan_secondary_rule.egress_vlan_tag,
			nircm->rule_flags,
			nircm->valid_flags,
			nircm->pppoe_rule.return_pppoe_session_id,
			nircm->pppoe_rule.return_pppoe_remote_mac,
			nircm->pppoe_rule.flow_pppoe_session_id,
			nircm->pppoe_rule.flow_pppoe_remote_mac,
			nircm->qos_rule.flow_qos_tag, nircm->qos_rule.flow_qos_tag,
			nircm->qos_rule.return_qos_tag, nircm->qos_rule.return_qos_tag,
			nircm->dscp_rule.flow_dscp,
			nircm->dscp_rule.return_dscp);

	/*
	 * Ref the connection before issuing an NSS rule
	 * This ensures that when the NSS responds to the command - which may even be immediately -
	 * the callback function can trust the correct ref was taken for its purpose.
	 * NOTE: remember that this will also implicitly hold the feci.
	 */
	ecm_db_connection_ref(fecnpi->ci);

	/*
	 * Call the rule create function
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecnpi->lock);
		DEBUG_ASSERT(fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecnpi, fecnpi->accel_mode);
		fecnpi->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * Release that ref!
	 */
	ecm_db_connection_deref(fecnpi->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecnpi->lock);
	DEBUG_ASSERT(fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecnpi, fecnpi->accel_mode);
	fecnpi->base.stats.driver_fail_total++;
	fecnpi->base.stats.driver_fail++;
	if (fecnpi->base.stats.driver_fail >= fecnpi->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Accel failed - driver fail limit\n", fecnpi);
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecnpi->lock);
	return;

non_ported_accel_bad_rule:
	;

	/*
	 * Jump to here when rule data is bad and an offload command cannot be constructed
	 */
	DEBUG_WARN("%p: Accel failed - bad rule\n", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	DEBUG_ASSERT(fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING, "%p: Accel mode unexpected: %d\n", fecnpi, fecnpi->accel_mode);
	fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_RULE;
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_destroy_callback()
 *	Callback for handling destroy ack/nack calls.
 */
static void ecm_front_end_ipv4_connection_non_ported_destroy_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_rule_destroy_msg *__attribute__((unused))nirdm = &nim->msg.rule_destroy;
	uint32_t serial = (uint32_t)app_data;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi;

	/*
	 * Is this a response to a destroy message?
	 */
	if (nim->cm.type != NSS_IPV4_TX_DESTROY_RULE_MSG) {
		DEBUG_ERROR("%p: non_ported destroy callback with improper type: %d\n", nim, nim->cm.type);
		return;
	}

	/*
	 * Look up ecm connection so that we can update the status.
	 */
	ci = ecm_db_connection_serial_find_and_ref(serial);
	if (!ci) {
		DEBUG_TRACE("%p: destroy callback, connection not found, serial: %u\n", nim, serial);
		return;
	}

	/*
	 * Release ref held for this ack/nack response.
	 * NOTE: It's okay to do this here, ci won't go away, because the ci is held as
	 * a result of the ecm_db_connection_serial_find_and_ref()
	 */
	ecm_db_connection_deref(ci);

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * Dump some useful trace information.
	 */
	DEBUG_TRACE("%p: decelerate response for connection: %p\n", fecnpi, fecnpi->ci);
	DEBUG_TRACE("%p: flow_ip: %pI4h:%d\n", fecnpi, &nirdm->tuple.flow_ip, nirdm->tuple.flow_ident);
	DEBUG_TRACE("%p: return_ip: %pI4h:%d\n", fecnpi, &nirdm->tuple.return_ip, nirdm->tuple.return_ident);
	DEBUG_TRACE("%p: protocol: %d\n", fecnpi, nirdm->tuple.protocol);

	spin_lock_bh(&fecnpi->lock);

	/*
	 * If decel is not still pending then it's possible that the NSS ended acceleration by some other reason e.g. flush
	 * In which case we cannot rely on the response we get here.
	 */
	if (fecnpi->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecnpi->lock);

		/*
		 * Release the connections.
		 */
		feci->deref(feci);
		ecm_db_connection_deref(ci);
		return;
	}

	DEBUG_TRACE("%p: response: %d\n", fecnpi, nim->cm.response);
	if (nim->cm.response != NSS_CMN_RESPONSE_ACK) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DECEL;
	} else {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}

	/*
	 * If connection became defunct then set mode so that no further accel/decel attempts occur.
	 */
	if (fecnpi->is_defunct) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
	}
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * NON_PORTED acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_non_ported_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_non_ported_accelerated_count >= 0, "Bad non_ported accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Release the connections.
	 */
	feci->deref(feci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_decelerate()
 *	Decelerate a connection
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_decelerate(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	struct nss_ipv4_msg nim;
	struct nss_ipv4_rule_destroy_msg *nirdm;
	ip_addr_t addr;
	nss_tx_status_t nss_tx_status;
	int protocol;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	/*
	 * For non-ported protocols we only support IPv6 in 4 or ESP
	 */
	protocol = ecm_db_connection_protocol_get(fecnpi->ci);
	if ((protocol != IPPROTO_IPV6) && (protocol != IPPROTO_ESP)) {
		DEBUG_TRACE("%p: unsupported protocol: %d\n", fecnpi, protocol);
		return;
	}

	/*
	 * If decelerate is in error or already pending then ignore
	 */
	spin_lock_bh(&fecnpi->lock);
	if (fecnpi->base.stats.decelerate_pending) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If acceleration is pending then we cannot decelerate right now or we will race with it
	 * Set a decelerate pending flag that will be actioned when the acceleration command is complete.
	 */
	if (fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecnpi->base.stats.decelerate_pending = true;
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * Can only decelerate if accelerated
	 * NOTE: This will also deny accel when the connection is in fail condition too.
	 */
	if (fecnpi->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * Initiate deceleration
	 */
	fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING;
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * Prepare deceleration message
	 */
	nss_ipv4_msg_init(&nim, NSS_IPV4_RX_INTERFACE, NSS_IPV4_TX_DESTROY_RULE_MSG,
			sizeof(struct nss_ipv4_rule_destroy_msg),
			(nss_ipv4_msg_callback_t *)ecm_front_end_ipv4_connection_non_ported_destroy_callback,
			(void *)ecm_db_connection_serial_get(fecnpi->ci));

	nirdm = &nim.msg.rule_destroy;
	nirdm->tuple.protocol = (int32_t)protocol;

	/*
	 * Get addressing information
	 */
	ecm_db_connection_from_address_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.flow_ip, addr);
	ecm_db_connection_to_address_nat_get(fecnpi->ci, addr);
	ECM_IP_ADDR_TO_HIN4_ADDR(nirdm->tuple.return_ip, addr);
	nirdm->tuple.flow_ident = ecm_db_connection_from_port_get(fecnpi->ci);
	nirdm->tuple.return_ident = ecm_db_connection_to_port_nat_get(fecnpi->ci);

	DEBUG_INFO("%p: Non-Ported Connection %p decelerate\n"
			"protocol: %d\n"
			"src_ip: %pI4:%d\n"
			"dest_ip: %pI4:%d\n",
			fecnpi, fecnpi->ci, protocol,
			&nirdm->tuple.flow_ip, nirdm->tuple.flow_ident,
			&nirdm->tuple.return_ip, nirdm->tuple.return_ident);

	/*
	 * Take a ref to the feci->ci so that it will persist until we get a response from the NSS.
	 * NOTE: This will implicitly hold the feci too.
	 */
	ecm_db_connection_ref(fecnpi->ci);

	/*
	 * Destroy the NSS connection cache entry.
	 */
	nss_tx_status = nss_ipv4_tx(ecm_front_end_ipv4_nss_ipv4_mgr, &nim);
	if (nss_tx_status == NSS_TX_SUCCESS) {
		spin_lock_bh(&fecnpi->lock);
		fecnpi->base.stats.driver_fail = 0;		/* Reset */
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * Release the ref take, NSS driver did not accept our command.
	 */
	ecm_db_connection_deref(fecnpi->ci);

	/*
	 * TX failed
	 */
	spin_lock_bh(&fecnpi->lock);
	fecnpi->base.stats.driver_fail_total++;
	fecnpi->base.stats.driver_fail++;
	if (fecnpi->base.stats.driver_fail >= fecnpi->base.stats.driver_fail_limit) {
		DEBUG_WARN("%p: Decel failed - driver fail limit\n", fecnpi);
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DRIVER;
	}
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_defunct_callback()
 *	Callback to be called when a non-ported connection has become defunct.
 */
static void ecm_front_end_ipv4_connection_non_ported_defunct_callback(void *arg)
{
	struct ecm_front_end_connection_instance *feci = (struct ecm_front_end_connection_instance *)arg;
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	spin_lock_bh(&fecnpi->lock);

	/*
	 * If connection has already become defunct, do nothing.
	 */
	if (fecnpi->is_defunct) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}
	fecnpi->is_defunct = true;

	/*
	 * If the connection is already in one of the fail modes, do nothing, keep the current accel_mode.
	 */
	if (ECM_FRONT_END_ACCELERATION_FAILED(fecnpi->accel_mode)) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If the connection is decel then ensure it will not attempt accel while defunct.
	 */
	if (fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DEFUNCT;
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If the connection is decel pending then decel operation is in progress anyway.
	 */
	if (fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_DECEL_PENDING) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If none of the cases mathes above, this means the connection is in one of the
	 * accel modes (accel or accel_pending) so we force a deceleration.
	 * NOTE: If the mode is accel pending then the decel will be actioned when that is completed.
	 */
	spin_unlock_bh(&fecnpi->lock);
	ecm_front_end_ipv4_connection_non_ported_front_end_decelerate(feci);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get()
 *	Get acceleration state
 */
static ecm_front_end_acceleration_mode_t ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;
	ecm_front_end_acceleration_mode_t state;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	state = fecnpi->accel_mode;
	spin_unlock_bh(&fecnpi->lock);
	return state;
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_action_seen()
 *	Acceleration action / activity has been seen for this connection.
 *
 * NOTE: Call the action_seen() method when the NSS has demonstrated that it has offloaded some data for a connection.
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_action_seen(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	DEBUG_INFO("%p: Action seen\n", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	fecnpi->base.stats.no_action_seen = 0;
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased()
 *	NSS has indicated that acceleration has stopped.
 *
 * NOTE: This is called in response to an NSS self-initiated termination of acceleration.
 * This must NOT be called because the ECM terminated the acceleration.
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	DEBUG_INFO("%p: accel ceased\n", fecnpi);

	spin_lock_bh(&fecnpi->lock);

	/*
	 * If we are in accel-pending state then the NSS has issued a flush out-of-order
	 * with the ACK/NACK we are actually waiting for.
	 * To work around this we record a "flush has already happened" and will action it when we finally get that ACK/NACK.
	 * GGG TODO This should eventually be removed when the NSS honours messaging sequence.
	 */
	if (fecnpi->accel_mode == ECM_FRONT_END_ACCELERATION_MODE_ACCEL_PENDING) {
		fecnpi->base.stats.flush_happened = true;
		fecnpi->base.stats.flush_happened_total++;
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If connection is no longer accelerated by the time we get here just ignore the command
	 */
	if (fecnpi->accel_mode != ECM_FRONT_END_ACCELERATION_MODE_ACCEL) {
		spin_unlock_bh(&fecnpi->lock);
		return;
	}

	/*
	 * If the no_action_seen counter was not reset then acceleration ended without any offload action
	 */
	if (fecnpi->base.stats.no_action_seen) {
		fecnpi->base.stats.no_action_seen_total++;
	}

	/*
	 * If the no_action_seen indicates successive cessations of acceleration without any offload action occuring
	 * then we fail out this connection
	 */
	if (fecnpi->base.stats.no_action_seen >= fecnpi->base.stats.no_action_seen_limit) {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_NO_ACTION;
	} else {
		fecnpi->accel_mode = ECM_FRONT_END_ACCELERATION_MODE_DECEL;
	}
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * Non-Ported acceleration ends
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_non_ported_accelerated_count--;	/* Protocol specific counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_non_ported_accelerated_count >= 0, "Bad non-ported accel counter\n");
	ecm_front_end_ipv4_accelerated_count--;		/* General running counter */
	DEBUG_ASSERT(ecm_front_end_ipv4_accelerated_count >= 0, "Bad accel counter\n");
	spin_unlock_bh(&ecm_front_end_ipv4_lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_ref()
 *	Ref a connection front end instance
 */
static void ecm_front_end_ipv4_connection_non_ported_front_end_ref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);
	spin_lock_bh(&fecnpi->lock);
	fecnpi->refs++;
	DEBUG_TRACE("%p: fecnpi ref %d\n", fecnpi, fecnpi->refs);
	DEBUG_ASSERT(fecnpi->refs > 0, "%p: ref wrap\n", fecnpi);
	spin_unlock_bh(&fecnpi->lock);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_deref()
 *	Deref a connection front end instance
 */
static int ecm_front_end_ipv4_connection_non_ported_front_end_deref(struct ecm_front_end_connection_instance *feci)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	spin_lock_bh(&fecnpi->lock);
	fecnpi->refs--;
	DEBUG_ASSERT(fecnpi->refs >= 0, "%p: ref wrap\n", fecnpi);

	if (fecnpi->refs > 0) {
		int refs = fecnpi->refs;
		spin_unlock_bh(&fecnpi->lock);
		DEBUG_TRACE("%p: fecnpi deref %d\n", fecnpi, refs);
		return refs;
	}
	spin_unlock_bh(&fecnpi->lock);

	/*
	 * We can now destroy the instance
	 */
	DEBUG_TRACE("%p: fecnpi final\n", fecnpi);
	DEBUG_CLEAR_MAGIC(fecnpi);
	kfree(fecnpi);

	/*
	 * Thread may be able to exit on object destruction
	 */
	return 0;
}

/*
 * ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get()
 *	Return an XML element containing the state of this Non ported front end instance
 */
static int ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get(struct ecm_front_end_connection_instance *feci, char *buf, int buf_sz)
{
	bool can_accel;
	ecm_front_end_acceleration_mode_t accel_mode;
	struct ecm_front_end_connection_mode_stats stats;
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)feci;

	DEBUG_CHECK_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC, "%p: magic failed", fecnpi);

	spin_lock_bh(&fecnpi->lock);
	can_accel = fecnpi->can_accel;
	accel_mode = fecnpi->accel_mode;
	memcpy(&stats, &feci->stats, sizeof(struct ecm_front_end_connection_mode_stats));
	spin_unlock_bh(&fecnpi->lock);

	return snprintf(buf, buf_sz, "<front_end_non_ported can_accel=\"%d\" accel_mode=\"%d\" decelerate_pending=\"%d\" flush_happened_total=\"%d\" no_action_seen_total=\"%d\" no_action_seen=\"%d\" no_action_seen_limit=\"%d\""
				" driver_fail_total=\"%d\" driver_fail=\"%d\" driver_fail_limit=\"%d\" nss_nack_total=\"%d\" nss_nack=\"%d\" nss_nack_limit=\"%d\"/>\n",
			can_accel,
			accel_mode,
			stats.decelerate_pending,
			stats.flush_happened_total,
			stats.no_action_seen_total,
			stats.no_action_seen,
			stats.no_action_seen_limit,
			stats.driver_fail_total,
			stats.driver_fail,
			stats.driver_fail_limit,
			stats.nss_nack_total,
			stats.nss_nack,
			stats.nss_nack_limit);
}

/*
 * ecm_front_end_ipv4_connection_non_ported_instance_alloc()
 *	Create a front end instance specific for NON_PORTED connection
 */
static struct ecm_front_end_ipv4_connection_non_ported_instance *ecm_front_end_ipv4_connection_non_ported_instance_alloc(
								struct ecm_db_connection_instance *ci,
								struct ecm_db_mapping_instance *src_mi,
								struct ecm_db_mapping_instance *dest_mi,
								bool can_accel)
{
	struct ecm_front_end_ipv4_connection_non_ported_instance *fecnpi;

	fecnpi = (struct ecm_front_end_ipv4_connection_non_ported_instance *)kzalloc(sizeof(struct ecm_front_end_ipv4_connection_non_ported_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!fecnpi) {
		DEBUG_WARN("NON_PORTED Front end alloc failed\n");
		return NULL;
	}

	/*
	 * Refs is 1 for the creator of the connection
	 */
	fecnpi->refs = 1;
	DEBUG_SET_MAGIC(fecnpi, ECM_FRONT_END_IPV4_CONNECTION_NON_PORTED_INSTANCE_MAGIC);
	spin_lock_init(&fecnpi->lock);

	fecnpi->can_accel = can_accel;
	fecnpi->accel_mode = (can_accel)? ECM_FRONT_END_ACCELERATION_MODE_DECEL : ECM_FRONT_END_ACCELERATION_MODE_FAIL_DENIED;
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	fecnpi->base.stats.no_action_seen_limit = ecm_front_end_ipv4_no_action_limit_default;
	fecnpi->base.stats.driver_fail_limit = ecm_front_end_ipv4_driver_fail_limit_default;
	fecnpi->base.stats.nss_nack_limit = ecm_front_end_ipv4_nack_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Copy reference to connection - no need to ref ci as ci maintains a ref to this instance instead (this instance persists for as long as ci does)
	 */
	fecnpi->ci = ci;

	/*
	 * Populate the methods and callbacks
	 */
	fecnpi->base.ref = ecm_front_end_ipv4_connection_non_ported_front_end_ref;
	fecnpi->base.deref = ecm_front_end_ipv4_connection_non_ported_front_end_deref;
	fecnpi->base.decelerate = ecm_front_end_ipv4_connection_non_ported_front_end_decelerate;
	fecnpi->base.accel_state_get = ecm_front_end_ipv4_connection_non_ported_front_end_accel_state_get;
	fecnpi->base.action_seen = ecm_front_end_ipv4_connection_non_ported_front_end_action_seen;
	fecnpi->base.accel_ceased = ecm_front_end_ipv4_connection_non_ported_front_end_accel_ceased;
	fecnpi->base.xml_state_get = ecm_front_end_ipv4_connection_non_ported_front_end_xml_state_get;

	return fecnpi;
}

/*
 * ecm_front_end_ipv4_assign_classifier()
 *	Instantiate and assign classifier of type upon the connection, also returning it if it could be allocated.
 */
static struct ecm_classifier_instance *ecm_front_end_ipv4_assign_classifier(struct ecm_db_connection_instance *ci, ecm_classifier_type_t type)
{
	DEBUG_TRACE("%p: Assign classifier of type: %d\n", ci, type);
	DEBUG_ASSERT(type != ECM_CLASSIFIER_TYPE_DEFAULT, "Must never need to instantiate default type in this way");

#ifdef ECM_CLASSIFIER_PCC_ENABLE
	if (type == ECM_CLASSIFIER_TYPE_PCC) {
		struct ecm_classifier_pcc_instance *pcci;
		pcci = ecm_classifier_pcc_instance_alloc(ci);
		if (!pcci) {
			DEBUG_TRACE("%p: Failed to create Parental Controls classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created Parental Controls classifier: %p\n", ci, pcci);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)pcci);
		return (struct ecm_classifier_instance *)pcci;
	}
#endif

#ifdef ECM_CLASSIFIER_NL_ENABLE
	if (type == ECM_CLASSIFIER_TYPE_NL) {
		struct ecm_classifier_nl_instance *cnli;
		cnli = ecm_classifier_nl_instance_alloc(ci);
		if (!cnli) {
			DEBUG_TRACE("%p: Failed to create Netlink classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created Netlink classifier: %p\n", ci, cnli);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)cnli);
		return (struct ecm_classifier_instance *)cnli;
	}
#endif

#ifdef ECM_CLASSIFIER_DSCP_ENABLE
	if (type == ECM_CLASSIFIER_TYPE_DSCP) {
		struct ecm_classifier_dscp_instance *cdscpi;
		cdscpi = ecm_classifier_dscp_instance_alloc(ci);
		if (!cdscpi) {
			DEBUG_TRACE("%p: Failed to create DSCP classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created DSCP classifier: %p\n", ci, cdscpi);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)cdscpi);
		return (struct ecm_classifier_instance *)cdscpi;
	}
#endif

#ifdef ECM_CLASSIFIER_HYFI_ENABLE
	if (type == ECM_CLASSIFIER_TYPE_HYFI) {
		struct ecm_classifier_hyfi_instance *chfi;
		chfi = ecm_classifier_hyfi_instance_alloc(ci);
		if (!chfi) {
			DEBUG_TRACE("%p: Failed to create HyFi classifier\n", ci);
			return NULL;
		}
		DEBUG_TRACE("%p: Created HyFi classifier: %p\n", ci, chfi);
		ecm_db_connection_classifier_assign(ci, (struct ecm_classifier_instance *)chfi);
		return (struct ecm_classifier_instance *)chfi;
	}
#endif

	// GGG TODO Add other classifier types.
	DEBUG_ASSERT(NULL, "%p: Unsupported type: %d\n", ci, type);
	return NULL;
}

/*
 * ecm_front_end_ipv4_reclassify()
 *	Signal reclassify upon the assigned classifiers.
 *
 * Classifiers that unassigned themselves we TRY to re-instantiate them.
 * Returns false if the function is not able to instantiate all missing classifiers.
 * This function does not release and references to classifiers in the assignments[].
 */
static bool ecm_front_end_ipv4_reclassify(struct ecm_db_connection_instance *ci, int assignment_count, struct ecm_classifier_instance *assignments[])
{
	ecm_classifier_type_t classifier_type;
	int i;
	bool full_reclassification = true;

	/*
	 * assignment_count will always be <= the number of classifier types available
	 */
	for (i = 0, classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT; i < assignment_count; ++i, ++classifier_type) {
		ecm_classifier_type_t aci_type;
		struct ecm_classifier_instance *aci;

		aci = assignments[i];
		aci_type = aci->type_get(aci);
		DEBUG_TRACE("%p: Reclassify: %d\n", ci, aci_type);
		aci->reclassify(aci);

		/*
		 * If the connection has a full complement of assigned classifiers then these will match 1:1 with the classifier_type (all in same order).
		 * If not, we have to create the missing ones.
		 */
		if (aci_type == classifier_type) {
			continue;
		}

		/*
		 * Need to instantiate the missing classifier types until we get to the same type as aci_type then we are back in sync to continue reclassification
		 */
		while (classifier_type != aci_type) {
			struct ecm_classifier_instance *naci;
			DEBUG_TRACE("%p: Instantiate missing type: %d\n", ci, classifier_type);
			DEBUG_ASSERT(classifier_type < ECM_CLASSIFIER_TYPES, "Algorithm bad");

			naci = ecm_front_end_ipv4_assign_classifier(ci, classifier_type);
			if (!naci) {
				full_reclassification = false;
			} else {
				naci->deref(naci);
			}

			classifier_type++;
		}
	}

	/*
	 * Add missing types
	 */
	for (; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
		struct ecm_classifier_instance *naci;
		DEBUG_TRACE("%p: Instantiate missing type: %d\n", ci, classifier_type);

		naci = ecm_front_end_ipv4_assign_classifier(ci, classifier_type);
		if (!naci) {
			full_reclassification = false;
		} else {
			naci->deref(naci);
		}
	}

	DEBUG_TRACE("%p: reclassify done: %u\n", ci, full_reclassification);
	return full_reclassification;
}

/*
 * ecm_front_end_ipv4_connection_regenerate()
 *	Re-generate a connection.
 *
 * Re-generating a connection involves re-evaluating the interface lists in case interface heirarchies have changed.
 * It also involves the possible triggering of classifier re-evaluation but only if all currently assigned
 * classifiers permit this operation.
 */
static bool ecm_front_end_ipv4_connection_regenerate(struct ecm_db_connection_instance *ci, ecm_tracker_sender_type_t sender,
							struct net_device *out_dev, struct net_device *out_dev_nat,
							struct net_device *in_dev, struct net_device *in_dev_nat)
{
	int i;
	bool reclassify_allowed;
	int32_t to_list_first;
	struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t to_nat_list_first;
	struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t from_list_first;
	struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	int32_t from_nat_list_first;
	struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
	ip_addr_t ip_src_addr;
	ip_addr_t ip_dest_addr;
	ip_addr_t ip_src_addr_nat;
	ip_addr_t ip_dest_addr_nat;
	int protocol;
	bool is_routed;
	uint8_t src_node_addr[ETH_ALEN];
	uint8_t dest_node_addr[ETH_ALEN];
	uint8_t src_node_addr_nat[ETH_ALEN];
	uint8_t dest_node_addr_nat[ETH_ALEN];
	int assignment_count;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];

	DEBUG_INFO("%p: re-gen needed\n", ci);

	/*
	 * We may need to swap the devices around depending on who the sender of the packet that triggered the re-gen is
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_DEST) {
		struct net_device *tmp_dev;

		/*
		 * This is a packet sent by the destination of the connection, i.e. it is a packet issued by the 'from' side of the connection.
		 */
		DEBUG_TRACE("%p: Re-gen swap devs\n", ci);
		tmp_dev = out_dev;
		out_dev = in_dev;
		in_dev = tmp_dev;

		tmp_dev = out_dev_nat;
		out_dev_nat = in_dev_nat;
		in_dev_nat = tmp_dev;
	}

	/*
	 * Update the interface lists - these may have changed, e.g. LAG path change etc.
	 * NOTE: We never have to change the usual mapping->host->node_iface arrangements for each side of the connection (to/from sides)
	 * This is because if these interfaces change then the connection is dead anyway.
	 * But a LAG slave might change the heirarchy the connection is using but the LAG master is still sane.
	 * If any of the new interface heirarchies cannot be created then simply set empty-lists as this will deny
	 * acceleration and ensure that a bad rule cannot be created.
	 * IMPORTANT: The 'sender' defines who has sent the packet that triggered this re-generation
	 */
	protocol = ecm_db_connection_protocol_get(ci);

	is_routed = ecm_db_connection_is_routed_get(ci);

	ecm_db_connection_from_address_get(ci, ip_src_addr);
	ecm_db_connection_from_address_nat_get(ci, ip_src_addr_nat);

	ecm_db_connection_to_address_get(ci, ip_dest_addr);
	ecm_db_connection_to_address_nat_get(ci, ip_dest_addr_nat);

	ecm_db_connection_from_node_address_get(ci, src_node_addr);
	ecm_db_connection_from_nat_node_address_get(ci, src_node_addr_nat);

	ecm_db_connection_to_node_address_get(ci, dest_node_addr);
	ecm_db_connection_to_nat_node_address_get(ci, dest_node_addr_nat);


	DEBUG_TRACE("%p: Update the 'from' interface heirarchy list\n", ci);
	from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, protocol, in_dev, is_routed, in_dev, src_node_addr, dest_node_addr);
	if (from_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_from_interfaces_reset(ci, from_list, from_list_first);
	ecm_db_connection_interfaces_deref(from_list, from_list_first);

	DEBUG_TRACE("%p: Update the 'from NAT' interface heirarchy list\n", ci);
	from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, protocol, in_dev_nat, is_routed, in_dev_nat, src_node_addr_nat, dest_node_addr_nat);
	if (from_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_from_nat_interfaces_reset(ci, from_nat_list, from_nat_list_first);
	ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);

	DEBUG_TRACE("%p: Update the 'to' interface heirarchy list\n", ci);
	to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, protocol, out_dev, is_routed, in_dev, dest_node_addr, src_node_addr);
	if (to_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_to_interfaces_reset(ci, to_list, to_list_first);
	ecm_db_connection_interfaces_deref(to_list, to_list_first);

	DEBUG_TRACE("%p: Update the 'to NAT' interface heirarchy list\n", ci);
	to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, protocol, out_dev_nat, is_routed, in_dev, dest_node_addr_nat, src_node_addr_nat);
	if (to_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
		goto ecm_ipv4_retry_regen;
	}

	ecm_db_connection_to_nat_interfaces_reset(ci, to_nat_list, to_nat_list_first);
	ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);

	/*
	 * Get list of assigned classifiers to reclassify.
	 * Remember: This also includes our default classifier too.
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);

	/*
	 * All of the assigned classifiers must permit reclassification.
	 */
	reclassify_allowed = true;
	for (i = 0; i < assignment_count; ++i) {
		DEBUG_TRACE("%p: Calling to reclassify: %p, type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
		if (!assignments[i]->reclassify_allowed(assignments[i])) {
			DEBUG_TRACE("%p: reclassify denied: %p, by type: %d\n", ci, assignments[i], assignments[i]->type_get(assignments[i]));
			reclassify_allowed = false;
			break;
		}
	}

	if (!reclassify_allowed) {
		/*
		 * Regeneration came to a successful conclusion even though reclassification was denied
		 */
		DEBUG_WARN("%p: re-gen denied\n", ci);\

		/*
		 * Release the assignments
		 */
		ecm_db_connection_assignments_release(assignment_count, assignments);
		return true;
	}

	/*
	 * Reclassify
	 */
	DEBUG_INFO("%p: reclassify\n", ci);
	if (!ecm_front_end_ipv4_reclassify(ci, assignment_count, assignments)) {
		/*
		 * We could not set up the classifiers to reclassify, it is safer to fail out and try again next time
		 */
		DEBUG_WARN("%p: Regeneration: reclassify failed\n", ci);
		ecm_db_connection_assignments_release(assignment_count, assignments);
		return false;
	}
	DEBUG_INFO("%p: reclassify success\n", ci);

	/*
	 * Release the assignments
	 */
	ecm_db_connection_assignments_release(assignment_count, assignments);
	return true;

ecm_ipv4_retry_regen:
	ecm_db_connection_classifier_generation_change(ci);
	return false;
}

/*
 * ecm_front_end_ipv4_tcp_process()
 *	Process a TCP packet
 */
static unsigned int ecm_front_end_ipv4_tcp_process(struct net_device *out_dev, struct net_device *out_dev_nat,
							struct net_device *in_dev, struct net_device *in_dev_nat,
							uint8_t *src_node_addr, uint8_t *src_node_addr_nat,
							uint8_t *dest_node_addr, uint8_t *dest_node_addr_nat,
							bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *iph,
							struct nf_conn *ct, ecm_tracker_sender_type_t sender, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct tcphdr *tcp_hdr;
	struct tcphdr tcp_hdr_buff;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	struct ecm_db_connection_instance *ci;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	/*
	 * Extract TCP header to obtain port information
	 */
	tcp_hdr = ecm_tracker_tcp_check_header_and_read(skb, iph, &tcp_hdr_buff);
	if (unlikely(!tcp_hdr)) {
		DEBUG_WARN("TCP packet header %p\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Now extract information, if we have conntrack then use that (which would already be in the tuples)
	 */
	if (unlikely(!ct)) {
		orig_tuple->src.u.tcp.port = tcp_hdr->source;
		orig_tuple->dst.u.tcp.port = tcp_hdr->dest;
		reply_tuple->src.u.tcp.port = tcp_hdr->dest;
		reply_tuple->dst.u.tcp.port = tcp_hdr->source;
	}

	/*
	 * Extract transport port information
	 * Refer to the ecm_front_end_ipv4_process() for information on how we extract this information.
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			src_port = ntohs(orig_tuple->src.u.tcp.port);
			dest_port = ntohs(orig_tuple->dst.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			src_port = ntohs(orig_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(orig_tuple->dst.u.tcp.port);
			dest_port = ntohs(reply_tuple->src.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			src_port = ntohs(orig_tuple->src.u.tcp.port);
			dest_port = ntohs(orig_tuple->dst.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	} else {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			dest_port = ntohs(orig_tuple->src.u.tcp.port);
			src_port = ntohs(orig_tuple->dst.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			dest_port = ntohs(orig_tuple->src.u.tcp.port);
			src_port_nat = ntohs(orig_tuple->dst.u.tcp.port);
			src_port = ntohs(reply_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			dest_port = ntohs(orig_tuple->src.u.tcp.port);
			src_port = ntohs(orig_tuple->dst.u.tcp.port);
			src_port_nat = ntohs(reply_tuple->src.u.tcp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.tcp.port);
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	}

	DEBUG_TRACE("TCP src: " ECM_IP_ADDR_DOT_FMT "(" ECM_IP_ADDR_DOT_FMT "):%d(%d), dest: " ECM_IP_ADDR_DOT_FMT "(" ECM_IP_ADDR_DOT_FMT "):%d(%d), dir %d\n",
			ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_src_addr_nat), src_port, src_port_nat, ECM_IP_ADDR_TO_DOT(ip_dest_addr),
			ECM_IP_ADDR_TO_DOT(ip_dest_addr_nat), dest_port, dest_port_nat, ecm_dir);

	/*
	 * Look up a connection
	 */
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_TCP, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_db_node_instance *src_ni;
		struct ecm_db_node_instance *dest_ni;
		struct ecm_db_node_instance *src_nat_ni;
		struct ecm_db_node_instance *dest_nat_ni;
		struct ecm_classifier_default_instance *dci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		struct ecm_front_end_connection_instance *feci;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New TCP connection from " ECM_IP_ADDR_DOT_FMT ":%u to " ECM_IP_ADDR_DOT_FMT ":%u\n",
				ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port);

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);

                /*
		 * Does this connection have a conntrack entry?
		 */
		if (ct) {
			unsigned int conn_count;

			/*
			 * If we have exceeded the connection limit (according to conntrack) then abort
			 * NOTE: Conntrack, when at its limit, will destroy a connection to make way for a new.
			 * Conntrack won't exceed its limit but ECM can due to it needing to hold connections while
			 * acceleration commands are in-flight.
			 * This means that ECM can 'fall behind' somewhat with the connection state wrt conntrack connection state.
			 * This is not seen as an issue since conntrack will have issued us with a destroy event for the flushed connection(s)
			 * and we will eventually catch up.
			 * Since ECM is capable of handling connections mid-flow ECM will pick up where it can.
			 */
			conn_count = (unsigned int)ecm_db_connection_count_get();
			if (conn_count >= nf_conntrack_max) {
				DEBUG_WARN("ECM Connection count limit reached: db: %u, ct: %u\n", conn_count, nf_conntrack_max);
				return NF_ACCEPT;
			}

			/*
			 * No point in establishing a connection for one that is closing
			 */
			spin_lock_bh(&ct->lock);
			if (ct->proto.tcp.state >= TCP_CONNTRACK_FIN_WAIT && ct->proto.tcp.state <= TCP_CONNTRACK_CLOSE) {
				spin_unlock_bh(&ct->lock);
				DEBUG_TRACE("%p: Connection in termination state %#X\n", ct, ct->proto.tcp.state);
				return NF_ACCEPT;
			}
			spin_unlock_bh(&ct->lock);
		} 

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination mappings.
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_TCP, in_dev, is_routed, in_dev, src_node_addr, dest_node_addr);
		if (from_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);

		DEBUG_TRACE("%p: Create source node\n", nci);
		src_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev, ip_src_addr, from_list, from_list_first, src_node_addr);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);
		if (!src_ni) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create source mapping\n", nci);
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_TCP, out_dev, is_routed, in_dev, dest_node_addr, src_node_addr);
		if (to_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);

		DEBUG_TRACE("%p: Create dest node\n", nci);
		dest_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev, ip_dest_addr, to_list, to_list_first, dest_node_addr);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);
		if (!dest_ni) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create dest mapping\n", nci);
		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination NAT mappings
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */
		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_TCP, in_dev_nat, is_routed, in_dev_nat, src_node_addr_nat, dest_node_addr_nat);
		if (from_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create source nat node\n", nci);
		src_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev_nat, ip_src_addr_nat, from_nat_list, from_nat_list_first, src_node_addr_nat);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);
		if (!src_nat_ni) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source nat node\n");
			return NF_ACCEPT;
		}

		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_TCP, out_dev_nat, is_routed, in_dev, dest_node_addr_nat, src_node_addr_nat);
		if (to_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);

		DEBUG_TRACE("%p: Create dest nat node\n", nci);
		dest_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev_nat, ip_dest_addr_nat, to_nat_list, to_nat_list_first, dest_node_addr_nat);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);
		if (!dest_nat_ni) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest nat node\n");
			return NF_ACCEPT;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_tcp_instance_alloc(nci, src_mi, dest_mi, can_accel);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_ACCEPT;
		}

		/*
		 * Every connection also needs a default classifier which is considered 'special' to be assigned
		 */
		dci = ecm_classifier_default_instance_alloc(nci, IPPROTO_TCP, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_classifier_assign(nci, (struct ecm_classifier_instance *)dci);

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_node_deref(dest_nat_ni);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_node_deref(src_nat_ni);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_node_deref(dest_ni);
				ecm_db_mapping_deref(src_mi);
				ecm_db_node_deref(src_ni);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_ACCEPT;
			}
		}

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_TCP, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;
			struct ecm_tracker_instance *ti;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					src_ni, dest_ni, src_nat_ni, dest_nat_ni,
					4, IPPROTO_TCP, ecm_dir,
					NULL /* final callback */,
					ecm_front_end_ipv4_connection_tcp_defunct_callback,
					tg, is_routed, nci);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New TCP connection created\n", ci);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(dest_nat_mi);
		ecm_db_node_deref(dest_nat_ni);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_node_deref(src_nat_ni);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_node_deref(dest_ni);
		ecm_db_mapping_deref(src_mi);
		ecm_db_node_deref(src_ni);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}

	/*
	 * Identify which side of the connection is sending.
	 * NOTE: This may be different than what sender is at the moment
	 * given the connection we have located.
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		if (!ecm_front_end_ipv4_connection_regenerate(ci, sender, out_dev, out_dev_nat, in_dev, in_dev_nat)) {
			DEBUG_WARN("%p: Re-generation failed\n", ci);
			ecm_db_connection_deref(ci);
			return NF_ACCEPT;
		}
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. All classifiers must action acceleration for accel to be honoured, any classifiers not sure of their relevance will stop acceleration.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.process_actions = 0;
	prevalent_pr.drop = false;
	prevalent_pr.flow_qos_tag = skb->priority;
	prevalent_pr.return_qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, iph, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, "
				"flow_qos_tag: %u, return_qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop,
				aci_pr.flow_qos_tag, aci_pr.return_qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: aci: %p, type: %d, flow qos tag: %u, return qos tag: %u\n",
					ci, aci, aci->type_get(aci), aci_pr.flow_qos_tag, aci_pr.return_qos_tag);
			prevalent_pr.flow_qos_tag = aci_pr.flow_qos_tag;
			prevalent_pr.return_qos_tag = aci_pr.return_qos_tag;
		}

		/*
		 * If any classifier denied DSCP remarking then that overrides every classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY) {
			DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark denied\n",
					ci, aci, aci->type_get(aci));
			prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY;
			prevalent_pr.process_actions &= ~ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
		}

		/*
		 * DSCP remark action, but only if it has not been denied by any classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
			if (!(prevalent_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY)) {
				DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark wanted, flow_dscp: %u, return dscp: %u\n",
						ci, aci, aci->type_get(aci), aci_pr.flow_dscp, aci_pr.return_dscp);
				prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
				prevalent_pr.flow_dscp = aci_pr.flow_dscp;
				prevalent_pr.return_dscp = aci_pr.return_dscp;
			}
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 * GGG TODO Should we use sender to identify whether to use flow or return qos tag?
	 */
	skb->priority = prevalent_pr.flow_qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_tcp_front_end_accelerate(feci, &prevalent_pr, ct);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_udp_process()
 *	Process a UDP packet
 */
static unsigned int ecm_front_end_ipv4_udp_process(struct net_device *out_dev, struct net_device *out_dev_nat,
							struct net_device *in_dev, struct net_device *in_dev_nat,
							uint8_t *src_node_addr, uint8_t *src_node_addr_nat,
							uint8_t *dest_node_addr, uint8_t *dest_node_addr_nat,
							bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *iph,
							struct nf_conn *ct, ecm_tracker_sender_type_t sender, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct udphdr *udp_hdr;
	struct udphdr udp_hdr_buff;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	struct ecm_db_connection_instance *ci;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	/*
	 * Extract UDP header to obtain port information
	 */
	udp_hdr = ecm_tracker_udp_check_header_and_read(skb, iph, &udp_hdr_buff);
	if (unlikely(!udp_hdr)) {
		DEBUG_WARN("Invalid UDP header in skb %p\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Now extract information, if we have conntrack then use that (which would already be in the tuples)
	 */
	if (unlikely(!ct)) {
		orig_tuple->src.u.udp.port = udp_hdr->source;
		orig_tuple->dst.u.udp.port = udp_hdr->dest;
		reply_tuple->src.u.udp.port = udp_hdr->dest;
		reply_tuple->dst.u.udp.port = udp_hdr->source;
	}

	/*
	 * Extract transport port information
	 * Refer to the ecm_front_end_ipv4_process() for information on how we extract this information.
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			src_port = ntohs(orig_tuple->src.u.udp.port);
			dest_port = ntohs(orig_tuple->dst.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.udp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			src_port = ntohs(orig_tuple->src.u.udp.port);
			dest_port_nat = ntohs(orig_tuple->dst.u.udp.port);
			dest_port = ntohs(reply_tuple->src.u.udp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			src_port = ntohs(orig_tuple->src.u.udp.port);
			dest_port = ntohs(orig_tuple->dst.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->src.u.udp.port);
			src_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	} else {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			dest_port = ntohs(orig_tuple->src.u.udp.port);
			src_port = ntohs(orig_tuple->dst.u.udp.port);
			src_port_nat = ntohs(reply_tuple->src.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			dest_port = ntohs(orig_tuple->src.u.udp.port);
			src_port_nat = ntohs(orig_tuple->dst.u.udp.port);
			src_port = ntohs(reply_tuple->src.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			dest_port = ntohs(orig_tuple->src.u.udp.port);
			src_port = ntohs(orig_tuple->dst.u.udp.port);
			src_port_nat = ntohs(reply_tuple->src.u.udp.port);
			dest_port_nat = ntohs(reply_tuple->dst.u.udp.port);
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	}
	DEBUG_TRACE("UDP src: " ECM_IP_ADDR_DOT_FMT ":%d, dest: " ECM_IP_ADDR_DOT_FMT ":%d, dir %d\n",
			ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port, ecm_dir);

	/*
	 * Look up a connection
	 */
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_UDP, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_db_node_instance *src_ni;
		struct ecm_db_node_instance *dest_ni;
		struct ecm_db_node_instance *src_nat_ni;
		struct ecm_db_node_instance *dest_nat_ni;
		struct ecm_classifier_default_instance *dci;
		struct ecm_front_end_connection_instance *feci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New UDP connection from " ECM_IP_ADDR_DOT_FMT ":%u to " ECM_IP_ADDR_DOT_FMT ":%u\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), src_port, ECM_IP_ADDR_TO_DOT(ip_dest_addr), dest_port);

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);

                /*
		 * Does this connection have a conntrack entry?
		 */
		if (ct) {
			unsigned int conn_count;

			/*
			 * If we have exceeded the connection limit (according to conntrack) then abort
			 * NOTE: Conntrack, when at its limit, will destroy a connection to make way for a new.
			 * Conntrack won't exceed its limit but ECM can due to it needing to hold connections while
			 * acceleration commands are in-flight.
			 * This means that ECM can 'fall behind' somewhat with the connection state wrt conntrack connection state.
			 * This is not seen as an issue since conntrack will have issued us with a destroy event for the flushed connection(s)
			 * and we will eventually catch up.
			 * Since ECM is capable of handling connections mid-flow ECM will pick up where it can.
			 */
			conn_count = (unsigned int)ecm_db_connection_count_get();
			if (conn_count >= nf_conntrack_max) {
				DEBUG_WARN("ECM Connection count limit reached: db: %u, ct: %u\n", conn_count, nf_conntrack_max);
				return NF_ACCEPT;
			}
		}

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination mappings.
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, IPPROTO_UDP, in_dev, is_routed, in_dev, src_node_addr, dest_node_addr);
		if (from_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);

		DEBUG_TRACE("%p: Create source node\n", nci);
		src_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev, ip_src_addr, from_list, from_list_first, src_node_addr);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);
		if (!src_ni) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create source mapping\n", nci);
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, IPPROTO_UDP, out_dev, is_routed, in_dev, dest_node_addr, src_node_addr);
		if (to_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);

		DEBUG_TRACE("%p: Create dest node\n", nci);
		dest_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev, ip_dest_addr, to_list, to_list_first, dest_node_addr);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);
		if (!dest_ni) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create dest mapping\n", nci);
		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination NAT mappings
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */
		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, IPPROTO_UDP, in_dev_nat, is_routed, in_dev_nat, src_node_addr_nat, dest_node_addr_nat);
		if (from_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create source nat node\n", nci);
		src_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev_nat, ip_src_addr_nat, from_nat_list, from_nat_list_first, src_node_addr_nat);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);
		if (!src_nat_ni) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source nat node\n");
			return NF_ACCEPT;
		}

		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, IPPROTO_UDP, out_dev_nat, is_routed, in_dev, dest_node_addr_nat, src_node_addr_nat);
		if (to_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);

		DEBUG_TRACE("%p: Create dest nat node\n", nci);
		dest_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev_nat, ip_dest_addr_nat, to_nat_list, to_nat_list_first, dest_node_addr_nat);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);
		if (!dest_nat_ni) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest nat node\n");
			return NF_ACCEPT;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_udp_instance_alloc(nci, src_mi, dest_mi, can_accel);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_ACCEPT;
		}

		/*
		 * Every connection also needs a default classifier
		 */
		dci = ecm_classifier_default_instance_alloc(nci, IPPROTO_UDP, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_classifier_assign(nci, (struct ecm_classifier_instance *)dci);

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_node_deref(dest_nat_ni);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_node_deref(src_nat_ni);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_node_deref(dest_ni);
				ecm_db_mapping_deref(src_mi);
				ecm_db_node_deref(src_ni);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_ACCEPT;
			}
		}

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, IPPROTO_UDP, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			struct ecm_tracker_instance *ti;
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					src_ni, dest_ni, src_nat_ni, dest_nat_ni,
					4, IPPROTO_UDP, ecm_dir,
					NULL /* final callback */,
					ecm_front_end_ipv4_connection_udp_defunct_callback,
					tg, is_routed, nci);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New UDP connection created\n", ci);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(dest_nat_mi);
		ecm_db_node_deref(dest_nat_ni);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_node_deref(src_nat_ni);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_node_deref(dest_ni);
		ecm_db_mapping_deref(src_mi);
		ecm_db_node_deref(src_ni);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}

	/*
	 * Identify which side of the connection is sending.
	 * NOTE: This may be different than what sender is at the moment
	 * given the connection we have located.
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		if (!ecm_front_end_ipv4_connection_regenerate(ci, sender, out_dev, out_dev_nat, in_dev, in_dev_nat)) {
			DEBUG_WARN("%p: Re-generation failed\n", ci);
			ecm_db_connection_deref(ci);
			return NF_ACCEPT;
		}
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. All classifiers must action acceleration for accel to be honoured, any classifiers not sure of their relevance will stop acceleration.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.process_actions = 0;
	prevalent_pr.drop = false;
	prevalent_pr.flow_qos_tag = skb->priority;
	prevalent_pr.return_qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, iph, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, "
				"flow_qos_tag: %u, return_qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop,
				aci_pr.flow_qos_tag, aci_pr.return_qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: aci: %p, type: %d, flow qos tag: %u, return qos tag: %u\n",
					ci, aci, aci->type_get(aci), aci_pr.flow_qos_tag, aci_pr.return_qos_tag);
			prevalent_pr.flow_qos_tag = aci_pr.flow_qos_tag;
			prevalent_pr.return_qos_tag = aci_pr.return_qos_tag;
		}

		/*
		 * If any classifier denied DSCP remarking then that overrides every classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY) {
			DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark denied\n",
					ci, aci, aci->type_get(aci));
			prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY;
			prevalent_pr.process_actions &= ~ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
		}

		/*
		 * DSCP remark action, but only if it has not been denied by any classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
			if (!(prevalent_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY)) {
				DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark wanted, flow_dscp: %u, return dscp: %u\n",
						ci, aci, aci->type_get(aci), aci_pr.flow_dscp, aci_pr.return_dscp);
				prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
				prevalent_pr.flow_dscp = aci_pr.flow_dscp;
				prevalent_pr.return_dscp = aci_pr.return_dscp;
			}
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 * GGG TODO Should we use sender to identify whether to use flow or return qos tag?
	 */
	skb->priority = prevalent_pr.flow_qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_udp_front_end_accelerate(feci, &prevalent_pr);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_non_ported_process()
 *	Process a protocol that does not have port based identifiers
 */
static unsigned int ecm_front_end_ipv4_non_ported_process(struct net_device *out_dev, struct net_device *out_dev_nat,
							struct net_device *in_dev, struct net_device *in_dev_nat,
							uint8_t *src_node_addr, uint8_t *src_node_addr_nat,
							uint8_t *dest_node_addr, uint8_t *dest_node_addr_nat,
							bool can_accel, bool is_routed, struct sk_buff *skb,
							struct ecm_tracker_ip_header *ip_hdr,
							struct nf_conn *ct, ecm_tracker_sender_type_t sender, ecm_db_direction_t ecm_dir,
							struct nf_conntrack_tuple *orig_tuple, struct nf_conntrack_tuple *reply_tuple,
							ip_addr_t ip_src_addr, ip_addr_t ip_dest_addr, ip_addr_t ip_src_addr_nat, ip_addr_t ip_dest_addr_nat)
{
	struct ecm_db_connection_instance *ci;
	int protocol;
	int src_port;
	int src_port_nat;
	int dest_port;
	int dest_port_nat;
	ip_addr_t match_addr;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;
	ecm_db_timer_group_t ci_orig_timer_group;
	struct ecm_classifier_process_response prevalent_pr;

	DEBUG_TRACE("Non-ported protocol src: " ECM_IP_ADDR_DOT_FMT ", dest: " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_dest_addr));

	/*
	 * Look up a connection.
	 */
	protocol = (int)orig_tuple->dst.protonum;
	if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
		src_port = 0;
		src_port_nat = 0;
		dest_port = 0;
		dest_port_nat = 0;
	} else {
		/*
		 * Do not accelerate the non-ported connections except the ones we handle.
		 */
		can_accel = false;

		/*
		 * port numbers are just the negative protocol number equivalents for now.
		 * GGG They could eventually be used as protocol specific identifiers such as icmp id's etc.
		 */
		src_port = -protocol;
		src_port_nat = -protocol;
		dest_port = -protocol;
		dest_port_nat = -protocol;
	}
	ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, protocol, src_port, dest_port);

	/*
	 * If there is no existing connection then create a new one.
	 */
	if (unlikely(!ci)) {
		struct ecm_db_mapping_instance *src_mi;
		struct ecm_db_mapping_instance *dest_mi;
		struct ecm_db_mapping_instance *src_nat_mi;
		struct ecm_db_mapping_instance *dest_nat_mi;
		struct ecm_db_node_instance *src_ni;
		struct ecm_db_node_instance *dest_ni;
		struct ecm_db_node_instance *src_nat_ni;
		struct ecm_db_node_instance *dest_nat_ni;
		struct ecm_classifier_default_instance *dci;
		struct ecm_front_end_connection_instance *feci;
		struct ecm_db_connection_instance *nci;
		ecm_classifier_type_t classifier_type;
		int32_t to_list_first;
		struct ecm_db_iface_instance *to_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t to_nat_list_first;
		struct ecm_db_iface_instance *to_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_list_first;
		struct ecm_db_iface_instance *from_list[ECM_DB_IFACE_HEIRARCHY_MAX];
		int32_t from_nat_list_first;
		struct ecm_db_iface_instance *from_nat_list[ECM_DB_IFACE_HEIRARCHY_MAX];

		DEBUG_INFO("New connection from " ECM_IP_ADDR_DOT_FMT " to " ECM_IP_ADDR_DOT_FMT "\n", ECM_IP_ADDR_TO_DOT(ip_src_addr), ECM_IP_ADDR_TO_DOT(ip_dest_addr));

		/*
		 * Before we attempt to create the connection are we being terminated?
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		if (ecm_front_end_ipv4_terminate_pending) {
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			DEBUG_WARN("Terminating\n");

			/*
			 * As we are terminating we just allow the packet to pass - it's no longer our concern
			 */
			return NF_ACCEPT;
		}
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
                
                 /*
		 * Does this connection have a conntrack entry?
		 */
		if (ct) {
			unsigned int conn_count;

			/*
			 * If we have exceeded the connection limit (according to conntrack) then abort
			 * NOTE: Conntrack, when at its limit, will destroy a connection to make way for a new.
			 * Conntrack won't exceed its limit but ECM can due to it needing to hold connections while
			 * acceleration commands are in-flight.
			 * This means that ECM can 'fall behind' somewhat with the connection state wrt conntrack connection state.
			 * This is not seen as an issue since conntrack will have issued us with a destroy event for the flushed connection(s)
			 * and we will eventually catch up.
			 * Since ECM is capable of handling connections mid-flow ECM will pick up where it can.
			 */
			conn_count = (unsigned int)ecm_db_connection_count_get();
			if (conn_count >= nf_conntrack_max) {
				DEBUG_WARN("ECM Connection count limit reached: db: %u, ct: %u\n", conn_count, nf_conntrack_max);
				return NF_ACCEPT;
			}
		}

		/*
		 * Now allocate the new connection
		 */
		nci = ecm_db_connection_alloc();
		if (!nci) {
			DEBUG_WARN("Failed to allocate connection\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination mappings.
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */
		DEBUG_TRACE("%p: Create the 'from' interface heirarchy list\n", nci);
		from_list_first = ecm_interface_heirarchy_construct(from_list, ip_dest_addr, ip_src_addr, protocol, in_dev, is_routed, in_dev, src_node_addr, dest_node_addr);
		if (from_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_interfaces_reset(nci, from_list, from_list_first);

		DEBUG_TRACE("%p: Create source node\n", nci);
		src_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev, ip_src_addr, from_list, from_list_first, src_node_addr);
		ecm_db_connection_interfaces_deref(from_list, from_list_first);
		if (!src_ni) {
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create source mapping\n", nci);
		src_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr, src_port);
		if (!src_mi) {
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to' interface heirarchy list\n", nci);
		to_list_first = ecm_interface_heirarchy_construct(to_list, ip_src_addr, ip_dest_addr, protocol, out_dev, is_routed, in_dev, dest_node_addr, src_node_addr);
		if (to_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_interfaces_reset(nci, to_list, to_list_first);

		DEBUG_TRACE("%p: Create dest node\n", nci);
		dest_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev, ip_dest_addr, to_list, to_list_first, dest_node_addr);
		ecm_db_connection_interfaces_deref(to_list, to_list_first);
		if (!dest_ni) {
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest node\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create dest mapping\n", nci);
		dest_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr, dest_port);
		if (!dest_mi) {
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Get the src and destination NAT mappings
		 * For this we also need the interface lists which we also set upon the new connection while we are at it.
		 * GGG TODO rework terms of "src/dest" - these need to be named consistently as from/to as per database terms.
		 * GGG TODO The empty list checks should not be needed, mapping_establish_and_ref() should fail out if there is no list anyway.
		 */

		/*
		 * NOTE: For SIT tunnels use the in_dev instead of in_dev_nat
		 */
		DEBUG_TRACE("%p: Create the 'from NAT' interface heirarchy list\n", nci);
		if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
			from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, protocol, in_dev, is_routed, in_dev, src_node_addr_nat, dest_node_addr_nat);
		} else {
			from_nat_list_first = ecm_interface_heirarchy_construct(from_nat_list, ip_dest_addr, ip_src_addr_nat, protocol, in_dev_nat, is_routed, in_dev, src_node_addr_nat, dest_node_addr_nat);
		}

		if (from_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'from NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_from_nat_interfaces_reset(nci, from_nat_list, from_nat_list_first);

		DEBUG_TRACE("%p: Create source nat node\n", nci);
		src_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(in_dev_nat, ip_src_addr_nat, from_nat_list, from_nat_list_first, src_node_addr_nat);
		ecm_db_connection_interfaces_deref(from_nat_list, from_nat_list_first);
		if (!src_nat_ni) {
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish source nat node\n");
			return NF_ACCEPT;
		}

		src_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_src_addr_nat, src_port_nat);
		if (!src_nat_mi) {
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish src nat mapping\n");
			return NF_ACCEPT;
		}

		DEBUG_TRACE("%p: Create the 'to NAT' interface heirarchy list\n", nci);
		to_nat_list_first = ecm_interface_heirarchy_construct(to_nat_list, ip_src_addr, ip_dest_addr_nat, protocol, out_dev_nat, is_routed, in_dev, dest_node_addr_nat, src_node_addr_nat);
		if (to_nat_list_first == ECM_DB_IFACE_HEIRARCHY_MAX) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to obtain 'to NAT' heirarchy list\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_to_nat_interfaces_reset(nci, to_nat_list, to_nat_list_first);

		DEBUG_TRACE("%p: Create dest nat node\n", nci);
		dest_nat_ni = ecm_front_end_ipv4_node_establish_and_ref(out_dev_nat, ip_dest_addr_nat, to_nat_list, to_nat_list_first, dest_node_addr_nat);
		ecm_db_connection_interfaces_deref(to_nat_list, to_nat_list_first);
		if (!dest_nat_ni) {
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest nat node\n");
			return NF_ACCEPT;
		}

		dest_nat_mi = ecm_front_end_ipv4_mapping_establish_and_ref(ip_dest_addr_nat, dest_port_nat);
		if (!dest_nat_mi) {
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to establish dest mapping\n");
			return NF_ACCEPT;
		}

		/*
		 * Connection must have a front end instance associated with it
		 */
		feci = (struct ecm_front_end_connection_instance *)ecm_front_end_ipv4_connection_non_ported_instance_alloc(nci, src_mi, dest_mi, can_accel);
		if (!feci) {
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate front end\n");
			return NF_ACCEPT;
		}

		/*
		 * Every connection also needs a default classifier
		 */
		dci = ecm_classifier_default_instance_alloc(nci, protocol, ecm_dir, src_port, dest_port);
		if (!dci) {
			feci->deref(feci);
			ecm_db_mapping_deref(dest_nat_mi);
			ecm_db_node_deref(dest_nat_ni);
			ecm_db_mapping_deref(src_nat_mi);
			ecm_db_node_deref(src_nat_ni);
			ecm_db_mapping_deref(dest_mi);
			ecm_db_node_deref(dest_ni);
			ecm_db_mapping_deref(src_mi);
			ecm_db_node_deref(src_ni);
			ecm_db_connection_deref(nci);
			DEBUG_WARN("Failed to allocate default classifier\n");
			return NF_ACCEPT;
		}
		ecm_db_connection_classifier_assign(nci, (struct ecm_classifier_instance *)dci);

		/*
		 * Every connection starts with a full complement of classifiers assigned.
		 * NOTE: Default classifier is a special case considered previously
		 */
		for (classifier_type = ECM_CLASSIFIER_TYPE_DEFAULT + 1; classifier_type < ECM_CLASSIFIER_TYPES; ++classifier_type) {
			struct ecm_classifier_instance *aci = ecm_front_end_ipv4_assign_classifier(nci, classifier_type);
			if (aci) {
				aci->deref(aci);
			} else {
				dci->base.deref((struct ecm_classifier_instance *)dci);
				feci->deref(feci);
				ecm_db_mapping_deref(dest_nat_mi);
				ecm_db_node_deref(dest_nat_ni);
				ecm_db_mapping_deref(src_nat_mi);
				ecm_db_node_deref(src_nat_ni);
				ecm_db_mapping_deref(dest_mi);
				ecm_db_node_deref(dest_ni);
				ecm_db_mapping_deref(src_mi);
				ecm_db_node_deref(src_ni);
				ecm_db_connection_deref(nci);
				DEBUG_WARN("Failed to allocate classifiers assignments\n");
				return NF_ACCEPT;
			}
		}

		/*
		 * Now add the connection into the database.
		 * NOTE: In an SMP situation such as ours there is a possibility that more than one packet for the same
		 * connection is being processed simultaneously.
		 * We *could* end up creating more than one connection instance for the same actual connection.
		 * To guard against this we now perform a mutex'd lookup of the connection + add once more - another cpu may have created it before us.
		 */
		spin_lock_bh(&ecm_front_end_ipv4_lock);
		ci = ecm_db_connection_find_and_ref(ip_src_addr, ip_dest_addr, protocol, src_port, dest_port);
		if (ci) {
			/*
			 * Another cpu created the same connection before us - use the one we just found
			 */
			spin_unlock_bh(&ecm_front_end_ipv4_lock);
			ecm_db_connection_deref(nci);
		} else {
			struct ecm_tracker_instance *ti;
			ecm_db_timer_group_t tg;
			ecm_tracker_sender_state_t src_state;
			ecm_tracker_sender_state_t dest_state;
			ecm_tracker_connection_state_t state;

			/*
			 * Ask tracker for timer group to set the connection to initially.
			 */
			ti = dci->tracker_get_and_ref(dci);
			ti->state_get(ti, &src_state, &dest_state, &state, &tg);
			ti->deref(ti);

			/*
			 * Add the new connection we created into the database
			 * NOTE: assign to a short timer group for now - it is the assigned classifiers responsibility to do this
			 */
			ecm_db_connection_add(nci, feci, src_mi, dest_mi, src_nat_mi, dest_nat_mi,
					src_ni, dest_ni, src_nat_ni, dest_nat_ni,
					4, protocol, ecm_dir,
					NULL /* final callback */,
					ecm_front_end_ipv4_connection_non_ported_defunct_callback,
					tg, is_routed, nci);

			spin_unlock_bh(&ecm_front_end_ipv4_lock);

			ci = nci;
			DEBUG_INFO("%p: New Non-ported protocol %d connection created\n", ci, protocol);
		}

		/*
		 * No longer need referenecs to the objects we created
		 */
		feci->deref(feci);
		dci->base.deref((struct ecm_classifier_instance *)dci);
		ecm_db_mapping_deref(dest_nat_mi);
		ecm_db_node_deref(dest_nat_ni);
		ecm_db_mapping_deref(src_nat_mi);
		ecm_db_node_deref(src_nat_ni);
		ecm_db_mapping_deref(dest_mi);
		ecm_db_node_deref(dest_ni);
		ecm_db_mapping_deref(src_mi);
		ecm_db_node_deref(src_ni);
	}

	/*
	 * Keep connection alive as we have seen activity
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}

	/*
	 * Identify which side of the connection is sending.
	 * NOTE: This may be different than what sender is at the moment
	 * given the connection we have located.
	 */
	ecm_db_connection_from_address_get(ci, match_addr);
	if (ECM_IP_ADDR_MATCH(ip_src_addr, match_addr)) {
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		sender = ECM_TRACKER_SENDER_TYPE_DEST;
	}

	/*
	 * Do we need to action generation change?
	 */
	if (unlikely(ecm_db_connection_classifier_generation_changed(ci))) {
		if (!ecm_front_end_ipv4_connection_regenerate(ci, sender, out_dev, out_dev_nat, in_dev, in_dev_nat)) {
			DEBUG_WARN("%p: Re-generation failed\n", ci);
			ecm_db_connection_deref(ci);
			return NF_ACCEPT;
		}
	}

	/*
	 * Iterate the assignments and call to process!
	 * Policy implemented:
	 * 1. Classifiers that say they are not relevant are unassigned and not actioned further.
	 * 2. Any drop command from any classifier is honoured.
	 * 3. Accel is never allowed for non-ported type connections.
	 * 4. Only the highest priority classifier, that actions it, will have its qos tag honoured.
	 * 5. Only the highest priority classifier, that actions it, will have its timer group honoured.
	 */
	DEBUG_TRACE("%p: process begin, skb: %p\n", ci, skb);
	prevalent_pr.process_actions = 0;
	prevalent_pr.drop = false;
	prevalent_pr.flow_qos_tag = skb->priority;
	prevalent_pr.return_qos_tag = skb->priority;
	prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL;
	prevalent_pr.timer_group = ci_orig_timer_group = ecm_db_connection_timer_group_get(ci);

	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_process_response aci_pr;
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: process: %p, type: %d\n", ci, aci, aci->type_get(aci));
		aci->process(aci, sender, ip_hdr, skb, &aci_pr);
		DEBUG_TRACE("%p: aci_pr: process actions: %x, became relevant: %u, relevance: %d, drop: %d, "
				"flow_qos_tag: %u, return_qos_tag: %u, accel_mode: %x, timer_group: %d\n",
				ci, aci_pr.process_actions, aci_pr.became_relevant, aci_pr.relevance, aci_pr.drop,
				aci_pr.flow_qos_tag, aci_pr.return_qos_tag, aci_pr.accel_mode, aci_pr.timer_group);

		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
			ecm_classifier_type_t aci_type;

			/*
			 * This classifier can be unassigned - PROVIDED it is not the default classifier
			 */
			aci_type = aci->type_get(aci);
			if (aci_type == ECM_CLASSIFIER_TYPE_DEFAULT) {
				continue;
			}

			DEBUG_INFO("%p: Classifier not relevant, unassign: %d", ci, aci_type);
			ecm_db_connection_classifier_unassign(ci, aci);
			continue;
		}

		/*
		 * Yes or Maybe relevant.
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DROP) {
			/*
			 * Drop command from any classifier is actioned.
			 */
			DEBUG_TRACE("%p: wants drop: %p, type: %d, skb: %p\n", ci, aci, aci->type_get(aci), skb);
			prevalent_pr.drop |= aci_pr.drop;
		}

		/*
		 * Accel mode permission
		 */
		if (aci_pr.relevance == ECM_CLASSIFIER_RELEVANCE_MAYBE) {
			/*
			 * Classifier not sure of its relevance - cannot accel yet
			 */
			DEBUG_TRACE("%p: accel denied by maybe: %p, type: %d\n", ci, aci, aci->type_get(aci));
			prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
		} else {
			if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_ACCEL_MODE) {
				if (aci_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_NO) {
					DEBUG_TRACE("%p: accel denied: %p, type: %d\n", ci, aci, aci->type_get(aci));
					prevalent_pr.accel_mode = ECM_CLASSIFIER_ACCELERATION_MODE_NO;
				}
				/* else yes or don't care about accel */
			}
		}

		/*
		 * Timer group (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_TIMER_GROUP) {
			DEBUG_TRACE("%p: timer group: %p, type: %d, group: %d\n", ci, aci, aci->type_get(aci), aci_pr.timer_group);
			prevalent_pr.timer_group = aci_pr.timer_group;
		}

		/*
		 * Qos tag (the last classifier i.e. the highest priority one) will 'win'
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG) {
			DEBUG_TRACE("%p: aci: %p, type: %d, flow qos tag: %u, return qos tag: %u\n",
					ci, aci, aci->type_get(aci), aci_pr.flow_qos_tag, aci_pr.return_qos_tag);
			prevalent_pr.flow_qos_tag = aci_pr.flow_qos_tag;
			prevalent_pr.return_qos_tag = aci_pr.return_qos_tag;
		}

		/*
		 * If any classifier denied DSCP remarking then that overrides every classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY) {
			DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark denied\n",
					ci, aci, aci->type_get(aci));
			prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY;
			prevalent_pr.process_actions &= ~ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
		}

		/*
		 * DSCP remark action, but only if it has not been denied by any classifier
		 */
		if (aci_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP) {
			if (!(prevalent_pr.process_actions & ECM_CLASSIFIER_PROCESS_ACTION_DSCP_DENY)) {
				DEBUG_TRACE("%p: aci: %p, type: %d, DSCP remark wanted, flow_dscp: %u, return dscp: %u\n",
						ci, aci, aci->type_get(aci), aci_pr.flow_dscp, aci_pr.return_dscp);
				prevalent_pr.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
				prevalent_pr.flow_dscp = aci_pr.flow_dscp;
				prevalent_pr.return_dscp = aci_pr.return_dscp;
			}
		}
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	/*
	 * Change timer group?
	 */
	if (ci_orig_timer_group != prevalent_pr.timer_group) {
		DEBUG_TRACE("%p: change timer group from: %d to: %d\n", ci, ci_orig_timer_group, prevalent_pr.timer_group);
		ecm_db_connection_defunct_timer_reset(ci, prevalent_pr.timer_group);
	}

	/*
	 * Drop?
	 */
	if (prevalent_pr.drop) {
		DEBUG_TRACE("%p: drop: %p\n", ci, skb);
		ecm_db_connection_data_totals_update_dropped(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);
		ecm_db_connection_deref(ci);
		return NF_ACCEPT;
	}
	ecm_db_connection_data_totals_update(ci, (sender == ECM_TRACKER_SENDER_TYPE_SRC)? true : false, skb->len, 1);

	/*
	 * Assign qos tag
	 * GGG TODO Should we use sender to identify whether to use flow or return qos tag?
	 */
	skb->priority = prevalent_pr.flow_qos_tag;
	DEBUG_TRACE("%p: skb priority: %u\n", ci, skb->priority);

#ifdef CONFIG_IPV6_SIT_6RD
#ifdef ECM_INTERFACE_SIT_ENABLE
	/*
	 * SIT tunnel acceleration needs create a rule to the nss firmware if the
	 *	tunnel's dest ip address is empty,it will get dest ip and the embedded ipv6's dest ip
	 *	address in the packet and send them to the nss firmware to accelerate the
	 *	traffic on the tun6rd interface.
	 */
	if (protocol == IPPROTO_IPV6
			&& prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_sit_set_peer((struct ecm_front_end_ipv4_connection_non_ported_instance *)feci, skb);
		feci->deref(feci);
	}
#endif
#endif

	/*
	 * Accelerate?
	 */
	if (prevalent_pr.accel_mode == ECM_CLASSIFIER_ACCELERATION_MODE_ACCEL) {
		struct ecm_front_end_connection_instance *feci;
		DEBUG_TRACE("%p: accel\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		ecm_front_end_ipv4_connection_non_ported_front_end_accelerate(feci, &prevalent_pr);
		feci->deref(feci);
	}
	ecm_db_connection_deref(ci);

	return NF_ACCEPT;
}

/*
 * ecm_front_end_ipv4_ip_process()
 *	Process IP datagram skb
 */
static unsigned int ecm_front_end_ipv4_ip_process(struct net_device *out_dev, struct net_device *in_dev,
							uint8_t *src_node_addr, uint8_t *dest_node_addr,
							bool can_accel, bool is_routed, struct sk_buff *skb)
{
	struct ecm_tracker_ip_header ip_hdr;
        struct nf_conn *ct;
        enum ip_conntrack_info ctinfo;
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	ecm_db_direction_t ecm_dir;
	ecm_tracker_sender_type_t sender;
	ip_addr_t ip_src_addr;
	ip_addr_t ip_dest_addr;
	ip_addr_t ip_src_addr_nat;
	ip_addr_t ip_dest_addr_nat;
	struct net_device *out_dev_nat;
	struct net_device *in_dev_nat;
	uint8_t *src_node_addr_nat;
	uint8_t *dest_node_addr_nat;

	/*
	 * Obtain the IP header from the skb
	 */
	if (!ecm_tracker_ip_check_header_and_read(&ip_hdr, skb)) {
		DEBUG_WARN("Invalid ip header in skb %p\n", skb);
		return NF_ACCEPT;
	}

	if (ip_hdr.fragmented) {
		DEBUG_TRACE("skb %p is fragmented\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Extract information, if we have conntrack then use that info as far as we can.
	 */
        ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(!ct)) {
		DEBUG_TRACE("%p: no ct\n", skb);
		orig_tuple.src.u3.ip = ip_hdr.h.v4_hdr.saddr;
		orig_tuple.dst.u3.ip = ip_hdr.h.v4_hdr.daddr;
		orig_tuple.dst.protonum = ip_hdr.protocol;
		reply_tuple.src.u3.ip = orig_tuple.dst.u3.ip;
		reply_tuple.dst.u3.ip = orig_tuple.src.u3.ip;
		sender = ECM_TRACKER_SENDER_TYPE_SRC;
	} else {
		if (unlikely(ct == &nf_conntrack_untracked)) {
			DEBUG_TRACE("%p: ct: untracked\n", skb);
			return NF_ACCEPT;
		}

        /* PPTP packet flow:  ip_forward => ip_forward_finish => ip_output(interface ppp0) 
         *                  => POST ROUTING hook(interface ppp0) => ip_finish_out => ppp_start_xmit => pptp_xmit
         *                  => ip_local_out => ip_output(interface eth0) 
         *                  => POSTROUTING hook(interface eth0) => ip_finish_out => dev_hard_start_xmit (eth0)
         *
         * skip second pass of pptp tunnel encapsulated traffic
         * to avoid deadlock of ppp_start_xmit and ppp_is_multilink when ECM go through twice POSTROUTING hook
         */
        if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_GRE) {
            return NF_ACCEPT;
        }

		/*
		 * If the conntrack connection is using a helper (i.e. Application Layer Gateway)
		 * then acceleration is denied (connection needs assistance from HLOS to function)
		 */
		if (nfct_help(ct)) {
			DEBUG_TRACE("%p: Connection has helper\n", ct);
			can_accel = false;
		}

		/*
		 * Extract conntrack connection information
		 */
		DEBUG_TRACE("%p: ct: %p, ctinfo: %x\n", skb, ct, ctinfo);
		orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		if (IP_CT_DIR_ORIGINAL == CTINFO2DIR(ctinfo)) {
			sender = ECM_TRACKER_SENDER_TYPE_SRC;
		} else {
			sender = ECM_TRACKER_SENDER_TYPE_DEST;
		}

		/*
		 * Is this a related connection?
		 */
		if ((ctinfo == IP_CT_RELATED) || (ctinfo == IP_CT_RELATED_REPLY)) {
			/*
			 * ct is related to the packet at hand.
			 * We can use the IP src/dest information and the direction information.
			 * We cannot use the protocol information from the ct (typically the packet at hand is ICMP error that is related to the ct we have here).
			 */
			orig_tuple.dst.protonum = ip_hdr.protocol;
			DEBUG_TRACE("%p: related ct, actual protocol: %u\n", skb, orig_tuple.dst.protonum);
		}
	}

	/*
	 * Work out if this packet involves NAT or not.
	 * If it does involve NAT then work out if this is an ingressing or egressing packet.
	 */
	if (orig_tuple.src.u3.ip != reply_tuple.dst.u3.ip) {
		/*
		 * Egressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_EGRESS_NAT;
	} else if (orig_tuple.dst.u3.ip != reply_tuple.src.u3.ip) {
		/*
		 * Ingressing NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_INGRESS_NAT;
	} else if (is_routed) {
		/*
		 * Non-NAT
		 */
		ecm_dir = ECM_DB_DIRECTION_NON_NAT;
	} else {
		/*
		 * Bridged
		 */
		ecm_dir = ECM_DB_DIRECTION_BRIDGED;
	}

	DEBUG_TRACE("IP Packet ORIGINAL src: %pI4 ORIGINAL dst: %pI4 protocol: %u, sender: %d ecm_dir: %d\n", &orig_tuple.src.u3.ip, &orig_tuple.dst.u3.ip, orig_tuple.dst.protonum, sender, ecm_dir);

	/*
	 * Get IP addressing information.  This same logic is applied when extracting port information too.
	 * This is tricky to do as what we are after is src and destination addressing that is non-nat but we also need the nat information too.
	 * INGRESS connections have their conntrack information reversed!
	 * We have to keep in mind the connection direction AND the packet direction in order to be able to work out what is what.
	 *
	 * ip_src_addr and ip_dest_addr MUST always be the NON-NAT endpoint addresses and reflect PACKET direction and not connection direction 'dir'.
	 *
	 * Examples 1 through 4 cater for NAT and NON-NAT in the INGRESS or EGRESS cases.
	 *
	 * Example 1:
	 * An 'original' direction packet to an egress connection from br-lan:192.168.0.133:12345 to eth0:80.132.221.34:80 via NAT'ing router mapping eth0:10.10.10.30:33333 looks like:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_dest_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_dest_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_src_addr_nat
	 *
	 *	in_dev would be br-lan - i.e. the device of ip_src_addr
	 *	out_dev would be eth0 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. out_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC======BR-LAN___ETH0====X====WAN_PC
	 *
	 *	src_node_addr refers to node address of of ip_src_addr_nat
	 *	src_node_addr_nat is set to src_node_addr
	 *	src_node_addr is then set to NULL as there is no node address available here for ip_src_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is the node of ip_dest_addr_nat which is the same as dest_node_addr
	 *
	 * Example 2:
	 * However an 'original' direction packet to an ingress connection from eth0:80.132.221.34:3321 to a LAN host (e.g. via DMZ) br-lan@192.168.0.133:12345 via NAT'ing router mapping eth0:10.10.10.30:12345 looks like:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_src_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_dest_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_src_addr_nat
	 *
	 *	in_dev would be eth0 - i.e. the device of ip_src_addr
	 *	out_dev would be br-lan - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. in_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC===X===BR-LAN___ETH0========WAN_PC
	 *
	 *	src_node_addr refers to node address of br-lan which is not useful
	 *	src_node_addr_nat AND src_node_addr become NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to NULL
	 *
	 * When dealing with reply packets this confuses things even more.  Reply packets to the above two examples are as follows:
	 *
	 * Example 3:
	 * A 'reply' direction packet to the egress connection above:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	orig_tuple->dst == 80.132.221.34:80		This becomes ip_src_addr
	 *	reply_tuple->src == 80.132.221.34:80		This becomes ip_src_addr_nat
	 *	reply_tuple->dest == 10.10.10.30:33333		This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be eth0 - i.e. the device of ip_src_addr
	 *	out_dev would be br-lan - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. in_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC===X===BR-LAN___ETH0========WAN_PC
	 *
	 *	src_node_addr refers to node address of br-lan which is not useful
	 *	src_node_addr_nat AND src_node_addr become NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to NULL
	 *
	 * Example 4:
	 * A 'reply' direction packet to the ingress connection above:
	 *	orig_tuple->src == 80.132.221.34:3321		This becomes ip_dest_addr
	 *	orig_tuple->dst == 10.10.10.30:12345		This becomes ip_src_addr_nat
	 *	reply_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	reply_tuple->dest == 80.132.221.34:3321		This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be br-lan - i.e. the device of ip_src_addr
	 *	out_dev would be eth0 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth0 - i.e. out_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth0 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN_PC======BR-LAN___ETH0====X====WAN_PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr_nat
	 *	src_node_addr_nat is set to src_node_addr
	 *	src_node_addr becomes NULL
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr also.
	 *
	 * The following examples are for BRIDGED cases:
	 *
	 * Example 5:
	 * An 'original' direction packet to an bridged connection from eth1:192.168.0.133:12345 to eth2:192.168.0.244:80 looks like:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_src_addr
	 *	orig_tuple->dst == 192.168.0.244:80		This becomes ip_dest_addr
	 *	reply_tuple->src == 192.168.0.244:80		This becomes ip_dest_addr_nat
	 *	reply_tuple->dest == 192.168.0.133:12345	This becomes ip_src_addr_nat
	 *
	 *	in_dev would be eth1 - i.e. the device of ip_src_addr
	 *	out_dev would be eth2 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth1 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth2 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN PC======ETH1___ETH2====X====LAN PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr
	 *	src_node_addr_nat is set to src_node_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr
	 *
	 * Example 6:
	 * An 'reply' direction packet to the bridged connection above:
	 *	orig_tuple->src == 192.168.0.133:12345		This becomes ip_dest_addr
	 *	orig_tuple->dst == 192.168.0.244:80		This becomes ip_src_addr
	 *	reply_tuple->src == 192.168.0.244:80		This becomes ip_src_addr_nat
	 *	reply_tuple->dest == 192.168.0.133:12345	This becomes ip_dest_addr_nat
	 *
	 *	in_dev would be eth2 - i.e. the device of ip_src_addr
	 *	out_dev would be eth1 - i.e. the device of ip_dest_addr
	 *	in_dev_nat would be eth2 - i.e. in_dev, the device of ip_src_addr_nat
	 *	out_dev_nat would be eth1 - i.e. out_dev, the device of ip_dest_addr_nat
	 *
	 *	From a Node address perspective we are at position X in the following topology:
	 *	LAN PC===X===ETH1___ETH2========LAN PC
	 *
	 *	src_node_addr refers to node address of ip_src_addr
	 *	src_node_addr_nat is set to src_node_addr
	 *
	 *	dest_node_addr refers to node address of ip_dest_addr
	 *	dest_node_addr_nat is set to dest_node_addr
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			/*
			 * Example 1
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = out_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;
			src_node_addr = NULL;

			dest_node_addr_nat = dest_node_addr;
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			/*
			 * Example 2
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = in_dev;
			out_dev_nat = in_dev;

			src_node_addr = NULL;
			src_node_addr_nat = NULL;

			dest_node_addr_nat = NULL;
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			/*
			 * Example 5
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = in_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;

			dest_node_addr_nat = dest_node_addr;
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	} else {
		if ((ecm_dir == ECM_DB_DIRECTION_EGRESS_NAT) || (ecm_dir == ECM_DB_DIRECTION_NON_NAT)) {
			/*
			 * Example 3
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat  = in_dev;
			out_dev_nat = in_dev;

			src_node_addr = NULL;
			src_node_addr_nat = NULL;

			dest_node_addr_nat = NULL;
		} else if (ecm_dir == ECM_DB_DIRECTION_INGRESS_NAT) {
			/*
			 * Example 4
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat = out_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;
			src_node_addr = NULL;

			dest_node_addr_nat = dest_node_addr;
		} else if (ecm_dir == ECM_DB_DIRECTION_BRIDGED) {
			/*
			 * Example 6
			 */
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr, orig_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr, orig_tuple.dst.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_src_addr_nat, reply_tuple.src.u3.ip);
			ECM_NIN4_ADDR_TO_IP_ADDR(ip_dest_addr_nat, reply_tuple.dst.u3.ip);

			in_dev_nat  = in_dev;
			out_dev_nat = out_dev;

			src_node_addr_nat = src_node_addr;

			dest_node_addr_nat = dest_node_addr;
		} else {
			DEBUG_ASSERT(false, "Unhandled ecm_dir: %d\n", ecm_dir);
		}
	}

	/*
	 * Non-unicast source or destination packets are ignored
	 * NOTE: Only need to check the non-nat src/dest addresses here.
	 */
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_dest_addr))) {
		DEBUG_TRACE("skb %p non-unicast daddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_dest_addr));
		return NF_ACCEPT;
	}
	if (unlikely(ecm_ip_addr_is_non_unicast(ip_src_addr))) {
		DEBUG_TRACE("skb %p non-unicast saddr " ECM_IP_ADDR_DOT_FMT "\n", skb, ECM_IP_ADDR_TO_DOT(ip_src_addr));
		return NF_ACCEPT;
	}

	/*
	 * Process IP specific protocol
	 * TCP and UDP are the most likliest protocols.
	 */
	if (likely(orig_tuple.dst.protonum == IPPROTO_TCP)) {
		return ecm_front_end_ipv4_tcp_process(out_dev, out_dev_nat,
				in_dev, in_dev_nat,
				src_node_addr, src_node_addr_nat,
				dest_node_addr, dest_node_addr_nat,
				can_accel, is_routed, skb,
				&ip_hdr,
				ct, sender, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
	} else if (likely(orig_tuple.dst.protonum == IPPROTO_UDP)) {
		return ecm_front_end_ipv4_udp_process(out_dev, out_dev_nat,
				in_dev, in_dev_nat,
				src_node_addr, src_node_addr_nat,
				dest_node_addr, dest_node_addr_nat,
				can_accel, is_routed, skb,
				&ip_hdr,
				ct, sender, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
	}
	return ecm_front_end_ipv4_non_ported_process(out_dev, out_dev_nat,
				in_dev, in_dev_nat,
				src_node_addr, src_node_addr_nat,
				dest_node_addr, dest_node_addr_nat,
				can_accel, is_routed, skb,
				&ip_hdr,
				ct, sender, ecm_dir,
				&orig_tuple, &reply_tuple,
				ip_src_addr, ip_dest_addr, ip_src_addr_nat, ip_dest_addr_nat);
}

/*
 * ecm_front_end_ipv4_post_routing_hook()
 *	Called for IP packets that are going out to interfaces after IP routing stage.
 */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,0))
static unsigned int ecm_front_end_ipv4_post_routing_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in_unused,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
#else
static unsigned int ecm_front_end_ipv4_post_routing_hook(const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in_unused,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
#endif
{
	struct net_device *in;
	bool can_accel = true;
	unsigned int result;

	DEBUG_TRACE("%p: Routing: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

#ifdef ECM_INTERFACE_PPP_ENABLE
	/*
	 * skip l2tp/pptp because we don't accelerate them
	 */
	if (ecm_interface_skip_l2tp_pptp(skb, out)) {
		return NF_ACCEPT;
	}
#endif

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		DEBUG_TRACE("Broadcast, ignoring: %p\n", skb);
		return NF_ACCEPT;
	}

	if (skb->pkt_type == PACKET_MULTICAST) {
		DEBUG_TRACE("Multicast, ignoring: %p\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came
	 */
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if (unlikely(!in)) {
		/*
		 * Locally sourced packets are not processed in ECM.
		 */
		return NF_ACCEPT;
	}

	DEBUG_TRACE("Post routing process skb %p, out: %p (%s), in: %p (%s)\n", skb, out, out->name, in, in->name);
	result = ecm_front_end_ipv4_ip_process((struct net_device *)out, in, NULL, NULL,
							can_accel, true, skb);
	dev_put(in);
	return result;
}

/*
 * ecm_front_end_ipv4_bridge_post_routing_hook()
 *	Called for packets that are going out to one of the bridge physical interfaces.
 *
 * These may have come from another bridged interface or from a non-bridged interface.
 * Conntrack information may be available or not if this skb is bridged.
 */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,0))
static unsigned int ecm_front_end_ipv4_bridge_post_routing_hook(unsigned int hooknum,
					struct sk_buff *skb,
					const struct net_device *in_unused,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
#else
static unsigned int ecm_front_end_ipv4_bridge_post_routing_hook(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct net_device *in_unused,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
#endif
{
	struct ethhdr *skb_eth_hdr;
	uint16_t eth_type;
	struct net_device *bridge;
	struct net_device *in;
	bool can_accel = true;
	unsigned int result;

	DEBUG_TRACE("%p: Bridge: %s\n", out, out->name);

	/*
	 * If operations have stopped then do not process packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		DEBUG_TRACE("Front end stopped\n");
		return NF_ACCEPT;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

#ifdef ECM_INTERFACE_PPP_ENABLE
	/*
	 * skip l2tp/pptp because we don't accelerate them
	 */
	if (ecm_interface_skip_l2tp_pptp(skb, out)) {
		return NF_ACCEPT;
	}
#endif

	/*
	 * Don't process broadcast or multicast
	 */
	if (skb->pkt_type == PACKET_BROADCAST) {
		DEBUG_TRACE("Broadcast, ignoring: %p\n", skb);
		return NF_ACCEPT;
	}

	if (skb->pkt_type == PACKET_MULTICAST) {
		DEBUG_TRACE("Multicast, ignoring: %p\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Check packet is an IP Ethernet packet
	 */
	skb_eth_hdr = eth_hdr(skb);
	if (!skb_eth_hdr) {
		DEBUG_TRACE("%p: Not Eth\n", skb);
		return NF_ACCEPT;
	}
	eth_type = ntohs(skb_eth_hdr->h_proto);
	if (unlikely(eth_type != 0x0800)) {
		DEBUG_TRACE("%p: Not IP\n", skb);
		return NF_ACCEPT;
	}

	/*
	 * Identify interface from where this packet came.
	 * There are three scenarios to consider here:
	 * 1. Packet came from a local source.
	 *	Ignore - local is not handled.
	 * 2. Packet came from a routed path.
	 *	Ignore - it was handled in INET post routing.
	 * 3. Packet is bridged from another port.
	 *	Process.
	 *
	 * Begin by identifying case 1.
	 * NOTE: We are given 'out' (which we implicitly know is a bridge port) so out interface's master is the 'bridge'.
	 */
	bridge = ecm_interface_get_and_hold_dev_master((struct net_device *)out);
	DEBUG_ASSERT(bridge, "Expected bridge\n");
	in = dev_get_by_index(&init_net, skb->skb_iif);
	if  (!in) {
		/*
		 * Case 1.
		 */
		DEBUG_TRACE("Local traffic: %p, ignoring traffic to bridge: %p (%s) \n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}
	dev_put(in);

	/*
	 * Case 2:
	 *	For routed packets the skb will have the src mac matching the bridge mac.
	 * Case 3:
	 *	If the packet was not local (case 1) or routed (case 2) then we process.
	 */
	in = br_port_dev_get(bridge, skb_eth_hdr->h_source);
	if (!in) {
		DEBUG_TRACE("skb: %p, no in device for bridge: %p (%s)\n", skb, bridge, bridge->name);
		dev_put(bridge);
		return NF_ACCEPT;
	}
	if (in == out) {
		DEBUG_TRACE("skb: %p, bridge: %p (%s), port bounce on %p (%s)\n", skb, bridge, bridge->name, out, out->name);
		dev_put(in);
		dev_put(bridge);
		return NF_ACCEPT;
	}
	if (!ecm_mac_addr_equal(skb_eth_hdr->h_source, bridge->dev_addr)) {
		/*
		 * Case 2: Routed trafffic would be handled by the INET post routing.
		 */
		DEBUG_TRACE("skb: %p, Ignoring routed packet to bridge: %p (%s)\n", skb, bridge, bridge->name);
		dev_put(in);
		dev_put(bridge);
		return NF_ACCEPT;
	}

	/*
	 * Process the packet, if we have this mac address in the fdb table.
	 * TODO: For the kernel versions later than 3.6.x, the API needs vlan id.
	 * 	 For now, we are passing 0, but this needs to be handled later.
	 */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,0))
	if (!br_fdb_has_entry((struct net_device *)out, skb_eth_hdr->h_dest)) {
#else
	if (!br_fdb_has_entry((struct net_device *)out, skb_eth_hdr->h_dest, 0)) {
#endif
		DEBUG_WARN("skb: %p, No fdb entry for this mac address %pM in the bridge: %p (%s)\n",
				skb, skb_eth_hdr->h_dest, bridge, bridge->name);
		dev_put(in);
		dev_put(bridge);
		return NF_ACCEPT;
	}

	DEBUG_TRACE("Bridge process skb: %p, bridge: %p (%s), In: %p (%s), Out: %p (%s)\n",
			skb, bridge, bridge->name, in, in->name, out, out->name);
	result = ecm_front_end_ipv4_ip_process((struct net_device *)out, in,
				skb_eth_hdr->h_source, skb_eth_hdr->h_dest, can_accel, false, skb);
	dev_put(in);
	dev_put(bridge);
	return result;
}

/* huluyao: dead mark to skip NSS, used by parental control. */
static unsigned int dead_ecm_front_end_ipv4_post_routing_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in_unused,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	if (((skb->mark & 0xffff0000) == 0xdead0000)) {
		return NF_ACCEPT;
	}

	return ecm_front_end_ipv4_post_routing_hook(hooknum, skb, in_unused, out, okfn);
}

/* huluyao: dead mark to skip NSS, used by parental control. */
static unsigned int dead_ecm_front_end_ipv4_bridge_post_routing_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in_unused,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	if (((skb->mark & 0xffff0000) == 0xdead0000)) {
		return NF_ACCEPT;
	}

	return ecm_front_end_ipv4_bridge_post_routing_hook(hooknum, skb, in_unused, out, okfn);
}

/*
 * ecm_front_end_ipv4_neigh_get()
 * 	Returns neighbour reference for a given IP address which must be released when you are done with it.
 *
 * Returns NULL on fail.
 */
static struct neighbour *ecm_front_end_ipv4_neigh_get(ip_addr_t addr)
{
	struct neighbour *neigh;
	struct rtable *rt;
	struct dst_entry *dst;
	__be32 ipv4_addr;

	ECM_IP_ADDR_TO_NIN4_ADDR(ipv4_addr, addr);
	rt = ip_route_output(&init_net, ipv4_addr, 0, 0, 0);
	if (IS_ERR(rt)) {
		return NULL;
	}
	dst = (struct dst_entry *)rt;
	neigh = dst_neigh_lookup(dst, &ipv4_addr);
	ip_rt_put(rt);
	return neigh;
}

/*
 * ecm_front_end_ipv4_net_dev_callback()
 *	Callback handler from the NSS.
 */
static void ecm_front_end_ipv4_net_dev_callback(void *app_data, struct nss_ipv4_msg *nim)
{
	struct nss_ipv4_conn_sync *sync;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	struct nf_conn_counter *acct;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	struct neighbour *neigh;
	ip_addr_t flow_ip;
	ip_addr_t return_ip_xlate;
	ip_addr_t return_ip;
	struct ecm_classifier_instance *assignments[ECM_CLASSIFIER_TYPES];
	int aci_index;
	int assignment_count;

	/*
	 * Only respond to sync messages
	 */
	if (nim->cm.type != NSS_IPV4_RX_CONN_STATS_SYNC_MSG) {
		DEBUG_TRACE("Ignoring nim: %p - not sync: %d", nim, nim->cm.type);
		return;
	}
	sync = &nim->msg.conn_stats;

	/*
	 * Look up ecm connection with a view to synchronising the connection, classifier and data tracker.
	 * Note that we use _xlate versions for destination - for egressing connections this would be the wan IP address,
	 * but for ingressing this would be the LAN side (non-nat'ed) address and is what we need for lookup of our connection.
	 */
	DEBUG_INFO("%p: NSS Sync, lookup connection using\n"
			"Protocol: %d\n" \
			"src_addr: %pI4h:%d\n" \
			"dest_addr: %pI4h:%d\n",
			sync,
			(int)sync->protocol,
			&sync->flow_ip, (int)sync->flow_ident,
			&sync->return_ip_xlate, (int)sync->return_ident_xlate);

	ECM_HIN4_ADDR_TO_IP_ADDR(flow_ip, sync->flow_ip);
	ECM_HIN4_ADDR_TO_IP_ADDR(return_ip_xlate, sync->return_ip_xlate);
	ci = ecm_db_connection_find_and_ref(flow_ip, return_ip_xlate, sync->protocol, (int)sync->flow_ident, (int)sync->return_ident_xlate);
	if (!ci) {
		DEBUG_TRACE("%p: NSS Sync: no connection\n", sync);
		goto sync_conntrack;
	}
	DEBUG_TRACE("%p: Sync conn %p\n", sync, ci);

	/*
	 * Keep connection alive and updated
	 */
	if (!ecm_db_connection_defunct_timer_touch(ci)) {
		ecm_db_connection_deref(ci);
		goto sync_conntrack;
	}

	/*
	 * Get the front end instance
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);

	if (sync->flow_tx_packet_count || sync->return_tx_packet_count) {
		DEBUG_TRACE("%p: flow_rx_packet_count: %u, flow_rx_byte_count: %u, return_rx_packet_count: %u, return_rx_byte_count: %u\n",
				ci, sync->flow_rx_packet_count, sync->flow_rx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);

		/*
		 * The amount of data *sent* by the ECM connection 'from' side is the amount the NSS has *received* in the 'flow' direction.
		 */
		ecm_db_connection_data_totals_update(ci, true, sync->flow_rx_byte_count, sync->flow_rx_packet_count);

		/*
		 * The amount of data *sent* by the ECM connection 'to' side is the amount the NSS has *received* in the 'return' direction.
		 */
		ecm_db_connection_data_totals_update(ci, false, sync->return_rx_byte_count, sync->return_rx_packet_count);

		/*
		 * As packets have been accelerated we have seen some action.
		 */
		feci->action_seen(feci);

		/*
		 * Update interface statistics
		 */
		ecm_interface_stats_update(ci, sync->flow_tx_packet_count, sync->flow_tx_byte_count, sync->flow_rx_packet_count, sync->flow_rx_byte_count,
						sync->return_tx_packet_count, sync->return_tx_byte_count, sync->return_rx_packet_count, sync->return_rx_byte_count);
	}

	/*
	 * Sync assigned classifiers
	 */
	assignment_count = ecm_db_connection_classifier_assignments_get_and_ref(ci, assignments);
	for (aci_index = 0; aci_index < assignment_count; ++aci_index) {
		struct ecm_classifier_instance *aci;

		aci = assignments[aci_index];
		DEBUG_TRACE("%p: sync to: %p, type: %d\n", feci, aci, aci->type_get(aci));
		aci->sync_to_v4(aci, sync);
	}
	ecm_db_connection_assignments_release(assignment_count, assignments);

	switch(sync->reason) {
	case NSS_IPV4_SYNC_REASON_DESTROY:
		/*
		 * This is the final sync from the NSS for a connection whose acceleration was
		 * terminated by the ecm.
		 * NOTE: We take no action here since that is performed by the destroy message ack.
		 */
		DEBUG_INFO("%p: ECM initiated final sync seen: %d\n", ci, sync->reason);
		break;
	case NSS_IPV4_SYNC_REASON_FLUSH:
	case NSS_IPV4_SYNC_REASON_EVICT:
		/*
		 * NSS has ended acceleration without instruction from the ECM.
		 */
		DEBUG_INFO("%p: NSS Initiated final sync seen: %d cause:%d\n", ci, sync->reason, sync->cause);

		/*
		 * NSS Decelerated the connection
		 */
		feci->accel_ceased(feci);
		break;
	default:

		/*
		 * Update the neighbour entry for source IP address
		 */
		neigh = ecm_front_end_ipv4_neigh_get(flow_ip);
		if (!neigh) {
			DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->flow_ip);
		} else {
			DEBUG_TRACE("Neighbour entry for %pI4h update: %p\n", &sync->flow_ip, neigh);
			neigh_update(neigh, NULL, neigh->nud_state, NEIGH_UPDATE_F_WEAK_OVERRIDE);
			neigh_release(neigh);
		}

		/*
		 * Update the neighbour entry for destination IP address
		 */
		ECM_HIN4_ADDR_TO_IP_ADDR(return_ip, sync->return_ip);
		neigh = ecm_front_end_ipv4_neigh_get(return_ip);
		if (!neigh) {
			DEBUG_WARN("Neighbour entry for %pI4h not found\n", &sync->return_ip);
		} else {
			DEBUG_TRACE("Neighbour entry for %pI4h update: %p\n", &sync->return_ip, neigh);
			neigh_update(neigh, NULL, neigh->nud_state, NEIGH_UPDATE_F_WEAK_OVERRIDE);
			neigh_release(neigh);
		}
	}

	/*
	 * If connection should be re-generated then we need to force a deceleration
	 */
	if (unlikely(ecm_db_connection_classifier_peek_generation_changed(ci))) {
		DEBUG_TRACE("%p: Connection generation changing, terminating acceleration", ci);
		feci->decelerate(feci);
	}

	feci->deref(feci);
	ecm_db_connection_deref(ci);

sync_conntrack:
	;

	/*
	 * Create a tuple so as to be able to look up a conntrack connection
	 */
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = htonl(sync->flow_ip);
	tuple.src.u.all = (__be16)htons(sync->flow_ident);
	tuple.src.l3num = AF_INET;

	tuple.dst.u3.ip = htonl(sync->return_ip);
	tuple.dst.dir = IP_CT_DIR_ORIGINAL;
	tuple.dst.protonum = (uint8_t)sync->protocol;
	tuple.dst.u.all = (__be16)htons(sync->return_ident);

	DEBUG_TRACE("Conntrack sync, lookup conntrack connection using\n"
			"Protocol: %d\n"
			"src_addr: %pI4:%d\n"
			"dest_addr: %pI4:%d\n",
			(int)tuple.dst.protonum,
			&tuple.src.u3.ip, (int)tuple.src.u.all,
			&tuple.dst.u3.ip, (int)tuple.dst.u.all);

	/*
	 * Look up conntrack connection
	 */
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (!h) {
		DEBUG_WARN("%p: NSS Sync: no conntrack connection\n", sync);
		return;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	DEBUG_TRACE("%p: NSS Sync: conntrack connection\n", ct);

	/*
	 * Only update if this is not a fixed timeout
	 */
	if (!test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status)) {
		unsigned long int delta_jiffies;

		/*
		 * Convert ms ticks from the NSS to jiffies.  We know that inc_ticks is small
		 * and we expect HZ to be small too so we can multiply without worrying about
		 * wrap-around problems.  We add a rounding constant to ensure that the different
		 * time bases don't cause truncation errors.
		 */
		DEBUG_ASSERT(HZ <= 100000, "Bad HZ\n");
		delta_jiffies = ((sync->inc_ticks * HZ) + (MSEC_PER_SEC / 2)) / MSEC_PER_SEC;

		spin_lock_bh(&ct->lock);
		ct->timeout.expires += delta_jiffies;
		spin_unlock_bh(&ct->lock);
	}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,0))
	acct = nf_conn_acct_find(ct);
#else
	acct = nf_conn_acct_find(ct)->counter;
#endif
	if (acct) {
		spin_lock_bh(&ct->lock);
		atomic64_add(sync->flow_rx_packet_count, &acct[IP_CT_DIR_ORIGINAL].packets);
		atomic64_add(sync->flow_rx_byte_count, &acct[IP_CT_DIR_ORIGINAL].bytes);

		atomic64_add(sync->return_rx_packet_count, &acct[IP_CT_DIR_REPLY].packets);
		atomic64_add(sync->return_rx_byte_count, &acct[IP_CT_DIR_REPLY].bytes);
		spin_unlock_bh(&ct->lock);
	}

	switch (sync->protocol) {
	case IPPROTO_TCP:
		spin_lock_bh(&ct->lock);
		if (ct->proto.tcp.seen[0].td_maxwin < sync->flow_max_window) {
			ct->proto.tcp.seen[0].td_maxwin = sync->flow_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_end - sync->flow_end) < 0) {
			ct->proto.tcp.seen[0].td_end = sync->flow_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[0].td_maxend - sync->flow_max_end) < 0) {
			ct->proto.tcp.seen[0].td_maxend = sync->flow_max_end;
		}
		if (ct->proto.tcp.seen[1].td_maxwin < sync->return_max_window) {
			ct->proto.tcp.seen[1].td_maxwin = sync->return_max_window;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_end - sync->return_end) < 0) {
			ct->proto.tcp.seen[1].td_end = sync->return_end;
		}
		if ((int32_t)(ct->proto.tcp.seen[1].td_maxend - sync->return_max_end) < 0) {
			ct->proto.tcp.seen[1].td_maxend = sync->return_max_end;
		}
		spin_unlock_bh(&ct->lock);
		break;
	}

	/*
	 * Release connection
	 */
	nf_ct_put(ct);
}

/*
 * struct nf_hook_ops ecm_front_end_ipv4_netfilter_hooks[]
 *	Hooks into netfilter packet monitoring points.
 */
static struct nf_hook_ops ecm_front_end_ipv4_netfilter_hooks[] __read_mostly = {
	/*
	 * Post routing hook is used to monitor packets going to interfaces that are NOT bridged in some way, e.g. packets to the WAN.
	 */
	{
		.hook           = dead_ecm_front_end_ipv4_post_routing_hook,
		.owner          = THIS_MODULE,
		.pf             = PF_INET,
		.hooknum        = NF_INET_POST_ROUTING,
		.priority       = NF_IP_PRI_NAT_SRC + 1,
	},

	/*
	 * The bridge post routing hook monitors packets going to interfaces that are part of a bridge arrangement.
	 * For example Wireles LAN (WLAN) and Wired LAN (LAN).
	 */
	{
		.hook		= dead_ecm_front_end_ipv4_bridge_post_routing_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_BRIDGE,
		.hooknum	= NF_BR_POST_ROUTING,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

/*
 * ecm_front_end_ipv4_connection_from_ct_get_and_ref()
 *	Return, if any, a connection given a ct
 */
static struct ecm_db_connection_instance *ecm_front_end_ipv4_connection_from_ct_get_and_ref(struct nf_conn *ct)
{
	struct nf_conntrack_tuple orig_tuple;
	struct nf_conntrack_tuple reply_tuple;
	ip_addr_t host1_addr;
	ip_addr_t host2_addr;
	int host1_port;
	int host2_port;
	int protocol;

	/*
	 * Look up the associated connection for this conntrack connection
	 */
	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	ECM_NIN4_ADDR_TO_IP_ADDR(host1_addr, orig_tuple.src.u3.ip);
	ECM_NIN4_ADDR_TO_IP_ADDR(host2_addr, reply_tuple.src.u3.ip);
	protocol = orig_tuple.dst.protonum;
	if (protocol == IPPROTO_TCP) {
		host1_port = ntohs(orig_tuple.src.u.tcp.port);
		host2_port = ntohs(reply_tuple.src.u.tcp.port);
	} else if (protocol == IPPROTO_UDP) {
		host1_port = ntohs(orig_tuple.src.u.udp.port);
		host2_port = ntohs(reply_tuple.src.u.udp.port);
	} else if ((protocol == IPPROTO_IPV6) || (protocol == IPPROTO_ESP)) {
		host1_port = 0;
		host2_port = 0;
	} else {
		host1_port = -protocol;
		host2_port = -protocol;
	}

	DEBUG_TRACE("%p: lookup src: " ECM_IP_ADDR_DOT_FMT ":%d, "
		    "dest: " ECM_IP_ADDR_DOT_FMT ":%d, "
		    "protocol %d\n",
		    ct,
		    ECM_IP_ADDR_TO_DOT(host1_addr),
		    host1_port,
		    ECM_IP_ADDR_TO_DOT(host2_addr),
		    host2_port,
		    protocol);

	return ecm_db_connection_find_and_ref(host1_addr,
					      host2_addr,
					      protocol,
					      host1_port,
					      host2_port);
}

/*
 * ecm_front_end_ipv4_conntrack_event_destroy()
 *	Handles conntrack destroy events
 */
static void ecm_front_end_ipv4_conntrack_event_destroy(struct nf_conn *ct)
{
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;

	DEBUG_INFO("Destroy event for ct: %p\n", ct);

	ci = ecm_front_end_ipv4_connection_from_ct_get_and_ref(ct);
	if (!ci) {
		DEBUG_TRACE("%p: not found\n", ct);
		return;
	}
	DEBUG_INFO("%p: Connection defunct %p\n", ct, ci);

	/*
	 * If this connection is accelerated then we need to issue a destroy command
	 */
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	feci->decelerate(feci);
	feci->deref(feci);

	/*
	 * Force destruction of the connection my making it defunct
	 */
	ecm_db_connection_make_defunct(ci);
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_conntrack_event_mark()
 *	Handles conntrack mark events
 */
static void ecm_front_end_ipv4_conntrack_event_mark(struct nf_conn *ct)
{
	struct ecm_db_connection_instance *ci;
	struct ecm_classifier_instance *__attribute__((unused))cls;

	DEBUG_INFO("Mark event for ct: %p\n", ct);

	/*
	 * Ignore transitions to zero
	 */
	if (ct->mark == 0) {
		return;
	}

	ci = ecm_front_end_ipv4_connection_from_ct_get_and_ref(ct);
	if (!ci) {
		DEBUG_TRACE("%p: not found\n", ct);
		return;
	}

#ifdef ECM_CLASSIFIER_NL_ENABLE
	/*
	 * As of now, only the Netlink classifier is interested in conmark changes
	 * GGG TODO Add a classifier method to propagate this information to any and all types of classifier.
	 */
	cls = ecm_db_connection_assigned_classifier_find_and_ref(ci, ECM_CLASSIFIER_TYPE_NL);
	if (cls) {
		ecm_classifier_nl_process_mark((struct ecm_classifier_nl_instance *)cls, ct->mark);
		cls->deref(cls);
	}
#endif

	/*
	 * All done
	 */
	ecm_db_connection_deref(ci);
}

/*
 * ecm_front_end_ipv4_conntrack_event()
 *	Callback event invoked when conntrack connection state changes, currently we handle destroy events to quickly release state
 */
int ecm_front_end_ipv4_conntrack_event(unsigned long events, struct nf_conn *ct)
{
	/*
	 * If operations have stopped then do not process event
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	if (unlikely(ecm_front_end_ipv4_stopped)) {
		DEBUG_WARN("Ignoring event - stopped\n");
		spin_unlock_bh(&ecm_front_end_ipv4_lock);
		return NOTIFY_DONE;
	}
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	if (!ct) {
		DEBUG_WARN("Error: no ct\n");
		return NOTIFY_DONE;
	}

	/*
	 * handle destroy events
	 */
	if (events & (1 << IPCT_DESTROY)) {
		DEBUG_TRACE("%p: Event is destroy\n", ct);
		ecm_front_end_ipv4_conntrack_event_destroy(ct);
	}

	/*
	 * handle mark change events
	 */
	if (events & (1 << IPCT_MARK)) {
		DEBUG_TRACE("%p: Event is mark\n", ct);
		ecm_front_end_ipv4_conntrack_event_mark(ct);
	}

	return NOTIFY_DONE;
}
EXPORT_SYMBOL(ecm_front_end_ipv4_conntrack_event);

/*
 * ecm_front_end_ipv4_get_stop()
 */
static ssize_t ecm_front_end_ipv4_get_stop(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_stopped;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

void ecm_front_end_ipv4_stop(int num)
{
	/*
	 * Operate under our locks and stop further processing of packets
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_stopped = num;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

}
EXPORT_SYMBOL(ecm_front_end_ipv4_stop);

/*
 * ecm_front_end_ipv4_set_stop()
 */
static ssize_t ecm_front_end_ipv4_set_stop(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_front_end_ipv4_stop = %d\n", num);

	ecm_front_end_ipv4_stop(num);

	return count;
}

/*
 * ecm_front_end_ipv4_get_udp_accelerated_count()
 */
static ssize_t ecm_front_end_ipv4_get_udp_accelerated_count(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_udp_accelerated_count;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_get_tcp_accelerated_count()
 */
static ssize_t ecm_front_end_ipv4_get_tcp_accelerated_count(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_tcp_accelerated_count;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_get_non_ported_accelerated_count()
 */
static ssize_t ecm_front_end_ipv4_get_non_ported_accelerated_count(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_non_ported_accelerated_count;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_get_accelerated_count()
 */
static ssize_t ecm_front_end_ipv4_get_accelerated_count(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_accelerated_count;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_get_no_action_limit_default()
 */
static ssize_t ecm_front_end_ipv4_get_no_action_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_no_action_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_set_no_action_limit_default()
 */
static ssize_t ecm_front_end_ipv4_set_no_action_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_front_end_ipv4_no_action_limit_default = %d\n", num);

	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_no_action_limit_default = num;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	return count;
}

/*
 * ecm_front_end_ipv4_get_driver_fail_limit_default()
 */
static ssize_t ecm_front_end_ipv4_get_driver_fail_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_driver_fail_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_set_driver_fail_limit_default()
 */
static ssize_t ecm_front_end_ipv4_set_driver_fail_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_front_end_ipv4_driver_fail_limit_default = %d\n", num);

	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_driver_fail_limit_default = num;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	return count;
}

/*
 * ecm_front_end_ipv4_get_nack_limit_default()
 */
static ssize_t ecm_front_end_ipv4_get_nack_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	num = ecm_front_end_ipv4_nack_limit_default;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_front_end_ipv4_set_nack_limit_default()
 */
static ssize_t ecm_front_end_ipv4_set_nack_limit_default(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) {
		return 0;
	}
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_front_end_ipv4_nack_limit_default = %d\n", num);

	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_nack_limit_default = num;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	return count;
}

/*
 * System device attributes
 */
static DEVICE_ATTR(stop, 0644, ecm_front_end_ipv4_get_stop, ecm_front_end_ipv4_set_stop);
static DEVICE_ATTR(no_action_limit_default, 0644, ecm_front_end_ipv4_get_no_action_limit_default, ecm_front_end_ipv4_set_no_action_limit_default);
static DEVICE_ATTR(driver_fail_limit_default, 0644, ecm_front_end_ipv4_get_driver_fail_limit_default, ecm_front_end_ipv4_set_driver_fail_limit_default);
static DEVICE_ATTR(nack_limit_default, 0644, ecm_front_end_ipv4_get_nack_limit_default, ecm_front_end_ipv4_set_nack_limit_default);
static DEVICE_ATTR(udp_accelerated_count, 0444, ecm_front_end_ipv4_get_udp_accelerated_count, NULL);
static DEVICE_ATTR(tcp_accelerated_count, 0444, ecm_front_end_ipv4_get_tcp_accelerated_count, NULL);
static DEVICE_ATTR(non_ported_accelerated_count, 0444, ecm_front_end_ipv4_get_non_ported_accelerated_count, NULL);
static DEVICE_ATTR(accelerated_count, 0444, ecm_front_end_ipv4_get_accelerated_count, NULL);

/*
 * System device attribute array.
 */
static struct device_attribute *ecm_front_end_ipv4_attrs[] = {
	&dev_attr_stop,
	&dev_attr_no_action_limit_default,
	&dev_attr_driver_fail_limit_default,
	&dev_attr_nack_limit_default,
	&dev_attr_udp_accelerated_count,
	&dev_attr_tcp_accelerated_count,
	&dev_attr_non_ported_accelerated_count,
	&dev_attr_accelerated_count
};

/*
 * Sub System node of the front end
 * Sysdevice control points can be found at /sys/devices/system/ecm_front_end_ipv4/ecm_front_end_ipv4X/
 */
static struct bus_type ecm_front_end_ipv4_subsys = {
	.name = "ecm_front_end_ipv4",
	.dev_name = "ecm_front_end_ipv4",
};

/*
 * ecm_front_end_ipv4_dev_release()
 *	This is a dummy release function for device.
 */
static void ecm_front_end_ipv4_dev_release(struct device *dev)
{

}

/*
 * ecm_front_end_ipv4_init()
 */
int ecm_front_end_ipv4_init(void)
{
	int result;
	int i;
	DEBUG_INFO("ECM Front end IPv4 init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_front_end_ipv4_lock);

	/*
	 * Register the Sub system
	 */
	result = subsys_system_register(&ecm_front_end_ipv4_subsys, NULL);
	if (result) {
		DEBUG_ERROR("Failed to register sub system %d\n", result);
		return result;
	}

	/*
	 * Register System device control
	 */
	memset(&ecm_front_end_ipv4_dev, 0, sizeof(ecm_front_end_ipv4_dev));
	ecm_front_end_ipv4_dev.id = 0;
	ecm_front_end_ipv4_dev.bus = &ecm_front_end_ipv4_subsys;
	ecm_front_end_ipv4_dev.release = ecm_front_end_ipv4_dev_release;
	result = device_register(&ecm_front_end_ipv4_dev);
	if (result) {
		DEBUG_ERROR("Failed to register System device %d\n", result);
		goto task_cleanup_1;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	for (i = 0; i < ARRAY_SIZE(ecm_front_end_ipv4_attrs); i++) {
		result = device_create_file(&ecm_front_end_ipv4_dev, ecm_front_end_ipv4_attrs[i]);
		if (result) {
			DEBUG_ERROR("Failed to register stop file %d\n", result);
			goto task_cleanup_2;
		}
	}

	/*
	 * Register netfilter hooks
	 */
	result = nf_register_hooks(ecm_front_end_ipv4_netfilter_hooks, ARRAY_SIZE(ecm_front_end_ipv4_netfilter_hooks));
	if (result < 0) {
		DEBUG_ERROR("Can't register netfilter hooks.\n");
		goto task_cleanup_2;
	}

	/*
	 * Register this module with the Linux NSS Network driver
	 */
	ecm_front_end_ipv4_nss_ipv4_mgr = nss_ipv4_notify_register(ecm_front_end_ipv4_net_dev_callback, NULL);

	return 0;

task_cleanup_2:
	while (--i >= 0) {
		device_remove_file(&ecm_front_end_ipv4_dev, ecm_front_end_ipv4_attrs[i]);
	}
	device_unregister(&ecm_front_end_ipv4_dev);
task_cleanup_1:
	bus_unregister(&ecm_front_end_ipv4_subsys);

	return result;
}
EXPORT_SYMBOL(ecm_front_end_ipv4_init);

/*
 * ecm_front_end_ipv4_exit()
 */
void ecm_front_end_ipv4_exit(void)
{
	int i;
	DEBUG_INFO("ECM Front end IPv4 Module exit\n");
	spin_lock_bh(&ecm_front_end_ipv4_lock);
	ecm_front_end_ipv4_terminate_pending = true;
	spin_unlock_bh(&ecm_front_end_ipv4_lock);

	/*
	 * Stop the network stack hooks
	 */
	nf_unregister_hooks(ecm_front_end_ipv4_netfilter_hooks,
			    ARRAY_SIZE(ecm_front_end_ipv4_netfilter_hooks));

	/*
	 * Unregister from the Linux NSS Network driver
	 */
	nss_ipv4_notify_unregister();

	for (i = 0; i < ARRAY_SIZE(ecm_front_end_ipv4_attrs); i++) {
		device_remove_file(&ecm_front_end_ipv4_dev, ecm_front_end_ipv4_attrs[i]);
	}

	device_unregister(&ecm_front_end_ipv4_dev);
	bus_unregister(&ecm_front_end_ipv4_subsys);
}
EXPORT_SYMBOL(ecm_front_end_ipv4_exit);
