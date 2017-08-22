/*
 **************************************************************************
 * Copyright (c) 2014-2015, The Linux Foundation.  All rights reserved.
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

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <linux/netfilter/xt_dscp.h>
#include <net/netfilter/nf_conntrack_dscpremark_ext.h>

#include <nss_api_if.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CLASSIFIER_DSCP_DEBUG_LEVEL

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_classifier_dscp.h"

/*
 * Magic numbers
 */
#define ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC 0xFA43

/*
 * struct ecm_classifier_dscp_instance
 * 	State to allow tracking of dynamic qos for a connection
 */
struct ecm_classifier_dscp_instance {
	struct ecm_classifier_instance base;			/* Base type */

	struct ecm_classifier_dscp_instance *next;		/* Next classifier state instance (for accouting and reporting purposes) */
	struct ecm_classifier_dscp_instance *prev;		/* Next classifier state instance (for accouting and reporting purposes) */

	uint32_t ci_serial;					/* RO: Serial of the connection */
	struct ecm_classifier_process_response process_response;/* Last process response computed */

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Operational control
 */
static bool ecm_classifier_dscp_enabled = true;			/* Operational behaviour */

/*
 * Management thread control
 */
static bool ecm_classifier_dscp_terminate_pending = false;	/* True when the user wants us to terminate */

/*
 * System device linkage
 */
static struct device ecm_classifier_dscp_dev;		/* System device linkage */

/*
 * Locking of the classifier structures
 */
static spinlock_t ecm_classifier_dscp_lock;			/* Protect SMP access. */

/*
 * List of our classifier instances
 */
static struct ecm_classifier_dscp_instance *ecm_classifier_dscp_instances = NULL;
								/* list of all active instances */
static int ecm_classifier_dscp_count = 0;			/* Tracks number of instances allocated */

/*
 * ecm_classifier_dscp_ref()
 *	Ref
 */
static void ecm_classifier_dscp_ref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	cdscpi = (struct ecm_classifier_dscp_instance *)ci;

	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);
	spin_lock_bh(&ecm_classifier_dscp_lock);
	cdscpi->refs++;
	DEBUG_TRACE("%p: cdscpi ref %d\n", cdscpi, cdscpi->refs);
	DEBUG_ASSERT(cdscpi->refs > 0, "%p: ref wrap\n", cdscpi);
	spin_unlock_bh(&ecm_classifier_dscp_lock);
}

/*
 * ecm_classifier_dscp_deref()
 *	Deref
 */
static int ecm_classifier_dscp_deref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	cdscpi = (struct ecm_classifier_dscp_instance *)ci;

	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);
	spin_lock_bh(&ecm_classifier_dscp_lock);
	cdscpi->refs--;
	DEBUG_ASSERT(cdscpi->refs >= 0, "%p: refs wrapped\n", cdscpi);
	DEBUG_TRACE("%p: DSCP classifier deref %d\n", cdscpi, cdscpi->refs);
	if (cdscpi->refs) {
		int refs = cdscpi->refs;
		spin_unlock_bh(&ecm_classifier_dscp_lock);
		return refs;
	}

	/*
	 * Object to be destroyed
	 */
	ecm_classifier_dscp_count--;
	DEBUG_ASSERT(ecm_classifier_dscp_count >= 0, "%p: ecm_classifier_dscp_count wrap\n", cdscpi);

	/*
	 * UnLink the instance from our list
	 */
	if (cdscpi->next) {
		cdscpi->next->prev = cdscpi->prev;
	}
	if (cdscpi->prev) {
		cdscpi->prev->next = cdscpi->next;
	} else {
		DEBUG_ASSERT(ecm_classifier_dscp_instances == cdscpi, "%p: list bad %p\n", cdscpi, ecm_classifier_dscp_instances);
		ecm_classifier_dscp_instances = cdscpi->next;
	}

	spin_unlock_bh(&ecm_classifier_dscp_lock);

	/*
	 * Final
	 */
	DEBUG_INFO("%p: Final DSCP classifier instance\n", cdscpi);
	kfree(cdscpi);

	return 0;
}

/*
 * ecm_classifier_dscp_process()
 *	Process new data for connection
 */
static void ecm_classifier_dscp_process(struct ecm_classifier_instance *aci, ecm_tracker_sender_type_t sender,
						struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb,
						struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	ecm_classifier_relevence_t relevance;
	struct ecm_db_connection_instance *ci = NULL;
	struct ecm_front_end_connection_instance *feci;
	ecm_front_end_acceleration_mode_t accel_mode;
	int protocol;
	uint32_t became_relevant = 0;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_ct_dscpremark_ext *dscpcte;
	uint32_t flow_qos_tag;
	uint32_t return_qos_tag;
	uint8_t flow_dscp;
	uint8_t return_dscp;
	bool dscp_marked = false;

	cdscpi = (struct ecm_classifier_dscp_instance *)aci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);

	/*
	 * Are we yet to decide if this instance is relevant to the connection?
	 */
	spin_lock_bh(&ecm_classifier_dscp_lock);
	relevance = cdscpi->process_response.relevance;

	/*
	 * Are we relevant?
	 */
	if (relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
		/*
		 * Lock still held
		 */
		goto dscp_classifier_out;
	}

	/*
	 * Yes or maybe relevant.
	 *
	 * Need to decide our relevance to this connection.
	 * We are only relevent to a connection iff:
	 * 1. We are enabled.
	 * 2. Connection can be accelerated.
	 * 3. Connection has a ct, ct has a dscp remark extension and the rule is validated.
	 * Any other condition and we are not and will stop analysing this connection.
	 */
	if (!ecm_classifier_dscp_enabled) {
		/*
		 * Lock still held
		 */
		cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
		goto dscp_classifier_out;
	}
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	/*
	 * Can we accelerate?
	 */
	ci = ecm_db_connection_serial_find_and_ref(cdscpi->ci_serial);
	if (!ci) {
		DEBUG_TRACE("%p: No ci found for %u\n", cdscpi, cdscpi->ci_serial);
		spin_lock_bh(&ecm_classifier_dscp_lock);
		cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
		goto dscp_classifier_out;
	}
	feci = ecm_db_connection_front_end_get_and_ref(ci);
	accel_mode = feci->accel_state_get(feci);
	feci->deref(feci);
	protocol = ecm_db_connection_protocol_get(ci);
	ecm_db_connection_deref(ci);
	if (ECM_FRONT_END_ACCELERATION_NOT_POSSIBLE(accel_mode)) {
		spin_lock_bh(&ecm_classifier_dscp_lock);
		cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
		goto dscp_classifier_out;
	}

	/*
	 * Is there a valid conntrack?
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		spin_lock_bh(&ecm_classifier_dscp_lock);
		cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
		goto dscp_classifier_out;
	}

	/*
	 * Is there a DSCPREMARK extension?
	 */
	spin_lock_bh(&ct->lock);
	dscpcte = nf_ct_dscpremark_ext_find(ct);
	if (!dscpcte) {
		spin_unlock_bh(&ct->lock);
		spin_lock_bh(&ecm_classifier_dscp_lock);
		cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_NO;
		goto dscp_classifier_out;
	}

	/*
	 * Was a DSCP rule enabled for the flow using the iptables 'DSCP'
	 * target?
	 */
	if (nf_conntrack_dscpremark_ext_get_dscp_rule_validity(ct)
				== NF_CT_DSCPREMARK_EXT_RULE_VALID) {
		dscp_marked = true;
	}

	/*
	 * Extract the priority and DSCP from skb and store into ct extension
	 * for each direction.
	 *
	 * For TCP flows, we would have the values for both the directions by
	 * the time the connection is established. For UDP flows, we copy
	 * over the values from one direction to another if we find the
	 * values for the other direction not set, which would be due to one
	 * of the following.
	 * a. We might not have seen a packet in the opposite direction
	 * b. There were no explicitly configured priority/DSCP for the opposite
	 *    direction.
	 *
	 */
	if (sender == ECM_TRACKER_SENDER_TYPE_SRC) {
		/*
		 * Record latest flow
		 */
		flow_qos_tag = skb->priority;
		dscpcte->flow_priority = flow_qos_tag;
		flow_dscp = ip_hdr->ds >> XT_DSCP_SHIFT;	/* NOTE: XT_DSCP_SHIFT is okay for V4 and V6 */
		dscpcte->flow_dscp = flow_dscp;

		/*
		 * Get the other side ready to return our PR
		 */
		if (protocol == IPPROTO_TCP) {
			return_qos_tag = dscpcte->reply_priority;
			return_dscp = dscpcte->reply_dscp;
		} else {
			/*
			 * Copy over the flow direction QoS
			 * and DSCP if the reply direction
			 * values are not set.
			 */
			if (dscpcte->reply_priority == 0) {
				return_qos_tag = flow_qos_tag;
			} else {
				return_qos_tag = dscpcte->reply_priority;
			}

			if (dscpcte->reply_dscp == 0) {
				return_dscp = flow_dscp;
			} else {
				return_dscp = dscpcte->reply_dscp;
			}
		}
		DEBUG_TRACE("Flow DSCP: %x Flow priority: %d, Return DSCP: %x Return priority: %d\n",
				dscpcte->flow_dscp, dscpcte->flow_priority, return_dscp, return_qos_tag);
	} else {
		/*
		 * Record latest return
		 */
		return_qos_tag = skb->priority;
		dscpcte->reply_priority = return_qos_tag;
		return_dscp = ip_hdr->ds >> XT_DSCP_SHIFT;	/* NOTE: XT_DSCP_SHIFT is okay for V4 and V6 */
		dscpcte->reply_dscp = return_dscp;

		/*
		 * Get the other side ready to return our PR
		 */
		if (protocol == IPPROTO_TCP) {
			flow_qos_tag = dscpcte->flow_priority;
			flow_dscp = dscpcte->flow_dscp;
		} else {
			/*
			 * Copy over the return direction QoS
			 * and DSCP if the flow direction
			 * values are not set.
			 */
			if (dscpcte->flow_priority == 0) {
				flow_qos_tag = return_qos_tag;
			} else {
				flow_qos_tag = dscpcte->flow_priority;
			}

			if (dscpcte->flow_dscp == 0) {
				flow_dscp = return_dscp;
			} else {
				flow_dscp = dscpcte->flow_dscp;
			}
		}
		DEBUG_TRACE("Return DSCP: %x Return priority: %d, Flow DSCP: %x Flow priority: %d\n",
				dscpcte->reply_dscp, dscpcte->reply_priority, flow_dscp, flow_qos_tag);
	}
	spin_unlock_bh(&ct->lock);

	/*
	 * We are relevant to the connection
	 */
	became_relevant = ecm_db_time_get();

	spin_lock_bh(&ecm_classifier_dscp_lock);
	cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_YES;
	cdscpi->process_response.became_relevant = became_relevant;

	cdscpi->process_response.process_actions = ECM_CLASSIFIER_PROCESS_ACTION_QOS_TAG;
	cdscpi->process_response.flow_qos_tag = flow_qos_tag;
	cdscpi->process_response.return_qos_tag = return_qos_tag;

	/*
	 * Check if we need to set DSCP
	 */
	if (dscp_marked) {
		cdscpi->process_response.flow_dscp = flow_dscp;
		cdscpi->process_response.return_dscp = return_dscp;
		cdscpi->process_response.process_actions |= ECM_CLASSIFIER_PROCESS_ACTION_DSCP;
	}

dscp_classifier_out:

	/*
	 * Return our process response
	 */
	*process_response = cdscpi->process_response;
	spin_unlock_bh(&ecm_classifier_dscp_lock);
}

/*
 * ecm_classifier_dscp_sync_to_v4()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_dscp_sync_to_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_conn_sync *sync)
{
	struct ecm_classifier_dscp_instance *cdscpi __attribute__((unused));

	cdscpi = (struct ecm_classifier_dscp_instance *)aci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed", cdscpi);
}

/*
 * ecm_classifier_dscp_sync_from_v4()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_dscp_sync_from_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_rule_create_msg *nircm)
{
	struct ecm_classifier_dscp_instance *cdscpi __attribute__((unused));

	cdscpi = (struct ecm_classifier_dscp_instance *)aci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed", cdscpi);
}

/*
 * ecm_classifier_dscp_sync_to_v6()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_dscp_sync_to_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_conn_sync *sync)
{
	struct ecm_classifier_dscp_instance *cdscpi __attribute__((unused));

	cdscpi = (struct ecm_classifier_dscp_instance *)aci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed", cdscpi);
}

/*
 * ecm_classifier_dscp_sync_from_v6()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_dscp_sync_from_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_rule_create_msg *nircm)
{
	struct ecm_classifier_dscp_instance *cdscpi __attribute__((unused));

	cdscpi = (struct ecm_classifier_dscp_instance *)aci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed", cdscpi);
}

/*
 * ecm_classifier_dscp_type_get()
 *	Get type of classifier this is
 */
static ecm_classifier_type_t ecm_classifier_dscp_type_get(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	cdscpi = (struct ecm_classifier_dscp_instance *)ci;

	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);
	return ECM_CLASSIFIER_TYPE_DSCP;
}

/*
 * ecm_classifier_dscp_last_process_response_get()
 *	Get result code returned by the last process call
 */
static void ecm_classifier_dscp_last_process_response_get(struct ecm_classifier_instance *ci,
							struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_dscp_instance *cdscpi;

	cdscpi = (struct ecm_classifier_dscp_instance *)ci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);

	spin_lock_bh(&ecm_classifier_dscp_lock);
	*process_response = cdscpi->process_response;
	spin_unlock_bh(&ecm_classifier_dscp_lock);
}

/*
 * ecm_classifier_dscp_reclassify_allowed()
 *	Indicate if reclassify is allowed
 */
static bool ecm_classifier_dscp_reclassify_allowed(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	cdscpi = (struct ecm_classifier_dscp_instance *)ci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);

	return true;
}

/*
 * ecm_classifier_dscp_reclassify()
 *	Reclassify
 */
static void ecm_classifier_dscp_reclassify(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	cdscpi = (struct ecm_classifier_dscp_instance *)ci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed\n", cdscpi);
}

/*
 * ecm_classifier_dscp_xml_state_get()
 *	Return an XML state element
 */
static int ecm_classifier_dscp_xml_state_get(struct ecm_classifier_instance *ci, char *buf, int buf_sz)
{
	struct ecm_classifier_dscp_instance *cdscpi;
	struct ecm_classifier_process_response process_response;
	int count;
	int total;

	cdscpi = (struct ecm_classifier_dscp_instance *)ci;
	DEBUG_CHECK_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC, "%p: magic failed", cdscpi);

	spin_lock_bh(&ecm_classifier_dscp_lock);
	process_response = cdscpi->process_response;
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	count = snprintf(buf, buf_sz, "<ecm_classifier_dscp>\n");
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total = count;
	buf_sz -= count;

	/*
	 * Output our last process response
	 */
	count = ecm_classifier_process_response_xml_state_get(buf + total, buf_sz, &process_response);
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	buf_sz -= count;

	/*
	 * Output our terminal element
	 */
	count = snprintf(buf + total, buf_sz, "</ecm_classifier_dscp>\n");
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_classifier_dscp_instance_alloc()
 *	Allocate an instance of the DSCP classifier
 */
struct ecm_classifier_dscp_instance *ecm_classifier_dscp_instance_alloc(struct ecm_db_connection_instance *ci)
{
	struct ecm_classifier_dscp_instance *cdscpi;

	/*
	 * Allocate the instance
	 */
	cdscpi = (struct ecm_classifier_dscp_instance *)kzalloc(sizeof(struct ecm_classifier_dscp_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!cdscpi) {
		DEBUG_WARN("Failed to allocate DSCP instance\n");
		return NULL;
	}

	DEBUG_SET_MAGIC(cdscpi, ECM_CLASSIFIER_DSCP_INSTANCE_MAGIC);
	cdscpi->refs = 1;
	cdscpi->base.process = ecm_classifier_dscp_process;
	cdscpi->base.sync_from_v4 = ecm_classifier_dscp_sync_from_v4;
	cdscpi->base.sync_to_v4 = ecm_classifier_dscp_sync_to_v4;
	cdscpi->base.sync_from_v6 = ecm_classifier_dscp_sync_from_v6;
	cdscpi->base.sync_to_v6 = ecm_classifier_dscp_sync_to_v6;
	cdscpi->base.type_get = ecm_classifier_dscp_type_get;
	cdscpi->base.last_process_response_get = ecm_classifier_dscp_last_process_response_get;
	cdscpi->base.reclassify_allowed = ecm_classifier_dscp_reclassify_allowed;
	cdscpi->base.reclassify = ecm_classifier_dscp_reclassify;
	cdscpi->base.xml_state_get = ecm_classifier_dscp_xml_state_get;
	cdscpi->base.ref = ecm_classifier_dscp_ref;
	cdscpi->base.deref = ecm_classifier_dscp_deref;
	cdscpi->ci_serial = ecm_db_connection_serial_get(ci);
	cdscpi->process_response.process_actions = 0;
	cdscpi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_MAYBE;

	spin_lock_bh(&ecm_classifier_dscp_lock);

	/*
	 * Final check if we are pending termination
	 */
	if (ecm_classifier_dscp_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_dscp_lock);
		DEBUG_INFO("%p: Terminating\n", ci);
		kfree(cdscpi);
		return NULL;
	}

	/*
	 * Link the new instance into our list at the head
	 */
	cdscpi->next = ecm_classifier_dscp_instances;
	if (ecm_classifier_dscp_instances) {
		ecm_classifier_dscp_instances->prev = cdscpi;
	}
	ecm_classifier_dscp_instances = cdscpi;

	/*
	 * Increment stats
	 */
	ecm_classifier_dscp_count++;
	DEBUG_ASSERT(ecm_classifier_dscp_count > 0, "%p: ecm_classifier_dscp_count wrap\n", cdscpi);
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	DEBUG_INFO("DSCP instance alloc: %p\n", cdscpi);
	return cdscpi;
}
EXPORT_SYMBOL(ecm_classifier_dscp_instance_alloc);

/*
 * ecm_classifier_dscp_get_enabled()
 */
static ssize_t ecm_classifier_dscp_get_enabled(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	DEBUG_TRACE("get enabled\n");
	spin_lock_bh(&ecm_classifier_dscp_lock);
	num = ecm_classifier_dscp_enabled;
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_classifier_dscp_set_enabled()
 */
static ssize_t ecm_classifier_dscp_set_enabled(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	char num_buf[12];
	int num;

	/*
	 * Get the number from buf into a properly z-termed number buffer
	 */
	if (count > 11) return 0;
	memcpy(num_buf, buf, count);
	num_buf[count] = '\0';
	sscanf(num_buf, "%d", &num);
	DEBUG_TRACE("ecm_classifier_dscp_enabled = %d\n", num);

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_classifier_dscp_lock);
	ecm_classifier_dscp_enabled = num;
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	return count;
}

/*
 * System device attributes for the dscp classifier itself.
 */
static DEVICE_ATTR(enabled, 0644, ecm_classifier_dscp_get_enabled, ecm_classifier_dscp_set_enabled);

/*
 * Sub system node of the ECM dscp classifier
 * Sys device control points can be found at /sys/devices/system/ecm_classifier_dscp/ecm_classifier_dscpX/
 */
static struct bus_type ecm_classifier_dscp_subsys = {
	.name = "ecm_classifier_dscp",
	.dev_name = "ecm_classifier_dscp",
};

/*
 * ecm_classifier_dscp_dev_release()
 *	This is a dummy release function for device.
 */
static void ecm_classifier_dscp_dev_release(struct device *dev)
{

}

/*
 * ecm_classifier_dscp_init()
 */
int ecm_classifier_dscp_init(void)
{
	int result;
	DEBUG_INFO("DSCP classifier Module init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_classifier_dscp_lock);

	/*
	 * Register the sub system
	 */
	result = subsys_system_register(&ecm_classifier_dscp_subsys, NULL);
	if (result) {
		DEBUG_WARN("Failed to register sub system\n");
		return result;
	}

	/*
	 * Register SYSFS device control
	 */
	memset(&ecm_classifier_dscp_dev, 0, sizeof(ecm_classifier_dscp_dev));
	ecm_classifier_dscp_dev.id = 0;
	ecm_classifier_dscp_dev.bus = &ecm_classifier_dscp_subsys;
	ecm_classifier_dscp_dev.release = &ecm_classifier_dscp_dev_release;
	result = device_register(&ecm_classifier_dscp_dev);
	if (result) {
		DEBUG_WARN("Failed to register system device\n");
		goto classifier_task_cleanup_1;
	}

	result = device_create_file(&ecm_classifier_dscp_dev, &dev_attr_enabled);
	if (result) {
		DEBUG_ERROR("Failed to register enabled system device file\n");
		goto classifier_task_cleanup_2;
	}

	return 0;

classifier_task_cleanup_2:
	device_unregister(&ecm_classifier_dscp_dev);
classifier_task_cleanup_1:
	bus_unregister(&ecm_classifier_dscp_subsys);

	return result;
}
EXPORT_SYMBOL(ecm_classifier_dscp_init);

/*
 * ecm_classifier_dscp_exit()
 */
void ecm_classifier_dscp_exit(void)
{
	DEBUG_INFO("DSCP classifier Module exit\n");

	spin_lock_bh(&ecm_classifier_dscp_lock);
	ecm_classifier_dscp_terminate_pending = true;
	spin_unlock_bh(&ecm_classifier_dscp_lock);

	device_remove_file(&ecm_classifier_dscp_dev, &dev_attr_enabled);
	device_unregister(&ecm_classifier_dscp_dev);
	bus_unregister(&ecm_classifier_dscp_subsys);
}
EXPORT_SYMBOL(ecm_classifier_dscp_exit);
