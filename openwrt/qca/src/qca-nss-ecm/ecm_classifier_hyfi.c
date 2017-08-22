/*
 **************************************************************************
 * Copyright (c) 2014, The Linux Foundation.  All rights reserved.
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

#include <nss_api_if.h>
#include <hyfi_ecm.h>
#include <hyfi_hash.h>

/*
 * Debug output levels
 * 0 = OFF
 * 1 = ASSERTS / ERRORS
 * 2 = 1 + WARN
 * 3 = 2 + INFO
 * 4 = 3 + TRACE
 */
#define DEBUG_LEVEL ECM_CLASSIFIER_HYFI_DEBUG_LEVEL

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_classifier.h"
#include "ecm_front_end_types.h"
#include "ecm_tracker_udp.h"
#include "ecm_tracker_tcp.h"
#include "ecm_db.h"
#include "ecm_classifier_hyfi.h"

/*
 * Magic numbers
 */
#define ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC 0xFE25

/*
 * Definitions
 */
#define ECM_CLASSIFIER_HYFI_STATE_INIT              ( 1 << 0 )
#define ECM_CLASSIFIER_HYFI_STATE_REGISTERED	    ( 1 << 1 )
#define ECM_CLASSIFIER_HYFI_STATE_IGNORE            ( 1 << 2 )

/*
 * struct ecm_classifier_hyfi_instance
 * 	State to allow tracking of dynamic qos for a connection
 */
struct ecm_classifier_hyfi_instance {
	struct ecm_classifier_instance base;			/* Base type */

	struct ecm_classifier_hyfi_instance *next;		/* Next classifier state instance (for accouting and reporting purposes) */
	struct ecm_classifier_hyfi_instance *prev;		/* Next classifier state instance (for accouting and reporting purposes) */

	uint32_t ci_serial;					/* RO: Serial of the connection */
	struct ecm_classifier_process_response process_response;/* Last process response computed */

	uint32_t hyfi_state;
	struct hyfi_ecm_flow_data_t flow;

	int refs;						/* Integer to trap we never go negative */
#if (DEBUG_LEVEL > 0)
	uint16_t magic;
#endif
};

/*
 * Listener for db events
 */
struct ecm_db_listener_instance *ecm_classifier_hyfi_li = NULL;

/*
 * Operational control
 */
static bool ecm_classifier_hyfi_enabled = true;		/* Operational behaviour */

/*
 * Management thread control
 */
static bool ecm_classifier_hyfi_terminate_pending = false;		/* True when the user wants us to terminate */

/*
 * System device linkage
 */
static struct device ecm_classifier_hyfi_dev;		/* System device linkage */

/*
 * Locking of the classifier structures
 */
static spinlock_t ecm_classifier_hyfi_lock;			/* Protect SMP access. */

/*
 * List of our classifier instances
 */
static struct ecm_classifier_hyfi_instance *ecm_classifier_hyfi_instances = NULL;
									/* list of all active instances */
static int ecm_classifier_hyfi_count = 0;					/* Tracks number of instances allocated */

/*
 * ecm_classifier_hyfi_ref()
 *	Ref
 */
static void ecm_classifier_hyfi_ref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;
	chfi = (struct ecm_classifier_hyfi_instance *)ci;

	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	chfi->refs++;
	DEBUG_TRACE("%p: chfi ref %d\n", chfi, chfi->refs);
	DEBUG_ASSERT(chfi->refs > 0, "%p: ref wrap\n", chfi);
	spin_unlock_bh(&ecm_classifier_hyfi_lock);
}

/*
 * ecm_classifier_hyfi_deref()
 *	Deref
 */
static int ecm_classifier_hyfi_deref(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;
	chfi = (struct ecm_classifier_hyfi_instance *)ci;

	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	chfi->refs--;
	DEBUG_ASSERT(chfi->refs >= 0, "%p: refs wrapped\n", chfi);
	DEBUG_TRACE("%p: HyFi classifier deref %d\n", chfi, chfi->refs);
	if (chfi->refs) {
		int refs = chfi->refs;
		spin_unlock_bh(&ecm_classifier_hyfi_lock);
		return refs;
	}

	/*
	 * Object to be destroyed
	 */
	ecm_classifier_hyfi_count--;
	DEBUG_ASSERT(ecm_classifier_hyfi_count >= 0, "%p: ecm_classifier_hyfi_count wrap\n", chfi);

	/*
	 * UnLink the instance from our list
	 */
	if (chfi->next) {
		chfi->next->prev = chfi->prev;
	}
	if (chfi->prev) {
		chfi->prev->next = chfi->next;
	} else {
		DEBUG_ASSERT(ecm_classifier_hyfi_instances == chfi, "%p: list bad %p\n", chfi, ecm_classifier_hyfi_instances);
		ecm_classifier_hyfi_instances = chfi->next;
	}
	chfi->next = NULL;
	chfi->prev = NULL;

	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	/*
	 * Final
	 */
	DEBUG_INFO("%p: Final HyFi classifier instance\n", chfi);
	kfree(chfi);

	return 0;
}

/*
 * ecm_classifier_hyfi_process()
 *	Process new data for connection
 */
static void ecm_classifier_hyfi_process(struct ecm_classifier_instance *aci, ecm_tracker_sender_type_t sender,
						struct ecm_tracker_ip_header *ip_hdr, struct sk_buff *skb,
						struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_hyfi_instance *chfi;
	ecm_classifier_relevence_t relevance;
	bool enabled;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;
	ecm_front_end_acceleration_mode_t accel_mode;
	uint32_t became_relevant = 0;

	chfi = (struct ecm_classifier_hyfi_instance *)aci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);

	/*
	 * Are we yet to decide if this instance is relevant to the connection?
	 */
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	relevance = chfi->process_response.relevance;
	if (relevance != ECM_CLASSIFIER_RELEVANCE_MAYBE) {
		/*
		 * We already know
		 * NOTE: Lock still held
		 */
		goto hyfi_classifier_out;
	}

	enabled = ecm_classifier_hyfi_enabled;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	/*
	 * Need to decide our relevance to this connection.
	 * If classifier is enabled and the front end says it can accel then we are "relevant".
	 * Any other condition and we are not and will stop analysing this connection.
	 */
	relevance = ECM_CLASSIFIER_RELEVANCE_NO;
	ci = ecm_db_connection_serial_find_and_ref(chfi->ci_serial);
	if (!ci) {
		DEBUG_TRACE("%p: No ci found for %u\n", chfi, chfi->ci_serial);
		accel_mode = ECM_FRONT_END_ACCELERATION_MODE_FAIL_DENIED;
	} else {
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		accel_mode = feci->accel_state_get(feci);
		feci->deref(feci);
		ecm_db_connection_deref(ci);
	}

	if (enabled && ECM_FRONT_END_ACCELERATION_POSSIBLE(accel_mode)) {
		relevance = ECM_CLASSIFIER_RELEVANCE_YES;
		became_relevant = ecm_db_time_get();
	}

	spin_lock_bh(&ecm_classifier_hyfi_lock);
	chfi->process_response.relevance = relevance;
	chfi->process_response.became_relevant = became_relevant;

hyfi_classifier_out:
	;

	/*
	 * Return our process response
	 */
	*process_response = chfi->process_response;
	if (relevance == ECM_CLASSIFIER_RELEVANCE_NO) {
		goto hyfi_classifier_done;
	}

	/*
	 * Fast path, already accelerated or ignored
	 */
	if (chfi->hyfi_state & (ECM_CLASSIFIER_HYFI_STATE_REGISTERED | ECM_CLASSIFIER_HYFI_STATE_IGNORE)) {
		goto hyfi_classifier_done;
	}

	/*
	 * Compute the hash
	 */
	if (unlikely(hyfi_hash_skbuf(skb, &chfi->flow.hash, &chfi->flow.flag, &chfi->flow.priority, &chfi->flow.seq))) {
		goto hyfi_classifier_done;
	}

	chfi->flow.ecm_serial = chfi->ci_serial;
	memcpy(&chfi->flow.sa, eth_hdr(skb)->h_source, ETH_ALEN);
	memcpy(&chfi->flow.da, eth_hdr(skb)->h_dest, ETH_ALEN);

	DEBUG_INFO("Flow serial: %d\nFlow hash: 0x%02x, priority 0x%08x, flag: %d\nSA: %pM\nDA: %pM\n\n",
			chfi->flow.ecm_serial, chfi->flow.hash, chfi->flow.priority, chfi->flow.flag,
			chfi->flow.sa, chfi->flow.da);

	chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_REGISTERED;

hyfi_classifier_done:
	;

	spin_unlock_bh(&ecm_classifier_hyfi_lock);
}

/*
 * ecm_classifier_hyfi_sync_to_v4()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_hyfi_sync_to_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_conn_sync *sync)
{
	struct ecm_classifier_hyfi_instance *chfi;
	struct ecm_db_connection_instance *ci;
	uint64_t num_packets = 0;
	uint64_t num_bytes = 0;
	int32_t ret;

	chfi = (struct ecm_classifier_hyfi_instance *)aci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed", chfi);

	if (chfi->hyfi_state &
			(ECM_CLASSIFIER_HYFI_STATE_IGNORE)) {
		return;
	}

	ci = ecm_db_connection_serial_find_and_ref(chfi->ci_serial);
	if (!ci) {
		DEBUG_TRACE("%p: No ci found for %u\n", chfi, chfi->ci_serial);
		return;
	}

	/*
	 * Update the stats on Hy-Fi side
	 */
	ecm_db_connection_data_stats_get(ci, NULL, &num_bytes,
			NULL, &num_packets,
			NULL, NULL,
			NULL, NULL );
	ecm_db_connection_deref(ci);

	DEBUG_INFO("UPDATE STATS: Flow serial: %d\nFlow hash: 0x%02x, priority 0x%08x, flag: %d\nSA: %pM\nDA: %pM\n\n",
			chfi->flow.ecm_serial, chfi->flow.hash, chfi->flow.priority, chfi->flow.flag,
			chfi->flow.sa, chfi->flow.da);

	DEBUG_INFO("num_bytes = %lld, num_packets = %lld\n", num_bytes, num_packets);

	ret = hyfi_ecm_update_stats(&chfi->flow, num_bytes, num_packets);

	if (ret < 0) {
		printk("%s: Fatal error\n", __func__);
		return;
	}

	switch(ret)
	{
	case 0: /* OK */
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_REGISTERED;
		break;

	case 1: /* Not interested */
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_IGNORE;
		break;

	case 2: /* Not attached, may be interested in the future */
	default:
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_INIT;
		break;
	}
}

/*
 * ecm_classifier_hyfi_sync_from_v4()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_hyfi_sync_from_v4(struct ecm_classifier_instance *aci, struct nss_ipv4_rule_create_msg *nircm)
{
	struct ecm_classifier_hyfi_instance *chfi;

	chfi = (struct ecm_classifier_hyfi_instance *)aci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed", chfi);
}

/*
 * ecm_classifier_hyfi_sync_to_v6()
 *	Front end is pushing NSS state to us
 */
static void ecm_classifier_hyfi_sync_to_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_conn_sync *sync)
{
	struct ecm_classifier_hyfi_instance *chfi;
	struct ecm_db_connection_instance *ci;
	uint64_t num_packets = 0;
	uint64_t num_bytes = 0;
	int32_t ret;

	chfi = (struct ecm_classifier_hyfi_instance *)aci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed", chfi);

	if (chfi->hyfi_state &
			(ECM_CLASSIFIER_HYFI_STATE_IGNORE)) {
		return;
	}

	ci = ecm_db_connection_serial_find_and_ref(chfi->ci_serial);
	if (!ci) {
		DEBUG_TRACE("%p: No ci found for %u\n", chfi, chfi->ci_serial);
		return;
	}

	/*
	 * Update the stats on Hy-Fi side
	 */
	ecm_db_connection_data_stats_get(ci, NULL, &num_bytes,
			NULL, &num_packets,
			NULL, NULL,
			NULL, NULL );
	ecm_db_connection_deref(ci);

	ret = hyfi_ecm_update_stats(&chfi->flow, num_bytes, num_packets);

	if (ret < 0) {
		DEBUG_ERROR("%s: Fatal error\n", __func__);
		return;
	}

	switch(ret)
	{
	case 0: /* OK */
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_REGISTERED;
		break;

	case 1: /* Not interested */
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_IGNORE;
		break;

	case 2: /* Not attached, may be interested in the future */
	default:
		chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_INIT;
		break;
	}
}

/*
 * ecm_classifier_hyfi_sync_from_v6()
 *	Front end is retrieving NSS state from us
 */
static void ecm_classifier_hyfi_sync_from_v6(struct ecm_classifier_instance *aci, struct nss_ipv6_rule_create_msg *nircm)
{
	struct ecm_classifier_hyfi_instance *chfi;

	chfi = (struct ecm_classifier_hyfi_instance *)aci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed", chfi);

}

/*
 * ecm_classifier_hyfi_type_get()
 *	Get type of classifier this is
 */
static ecm_classifier_type_t ecm_classifier_hyfi_type_get(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;
	chfi = (struct ecm_classifier_hyfi_instance *)ci;

	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);
	return ECM_CLASSIFIER_TYPE_HYFI;
}

/*
 * ecm_classifier_hyfi_last_process_response_get()
 *	Get result code returned by the last process call
 */
static void ecm_classifier_hyfi_last_process_response_get(struct ecm_classifier_instance *ci,
							struct ecm_classifier_process_response *process_response)
{
	struct ecm_classifier_hyfi_instance *chfi;

	chfi = (struct ecm_classifier_hyfi_instance *)ci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);

	spin_lock_bh(&ecm_classifier_hyfi_lock);
	*process_response = chfi->process_response;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);
}

/*
 * ecm_classifier_hyfi_reclassify_allowed()
 *	Indicate if reclassify is allowed
 */
static bool ecm_classifier_hyfi_reclassify_allowed(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;
	chfi = (struct ecm_classifier_hyfi_instance *)ci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);

	return true;
}

/*
 * ecm_classifier_hyfi_reclassify()
 *	Reclassify
 */
static void ecm_classifier_hyfi_reclassify(struct ecm_classifier_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;
	chfi = (struct ecm_classifier_hyfi_instance *)ci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed\n", chfi);
}

/*
 * ecm_classifier_hyfi_xml_state_get()
 *	Return an XML state element
 */
static int ecm_classifier_hyfi_xml_state_get(struct ecm_classifier_instance *ci, char *buf, int buf_sz)
{
	struct ecm_classifier_hyfi_instance *chfi;
	struct ecm_classifier_process_response process_response;
	int count;
	int total;

	chfi = (struct ecm_classifier_hyfi_instance *)ci;
	DEBUG_CHECK_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC, "%p: magic failed", chfi);

	spin_lock_bh(&ecm_classifier_hyfi_lock);
	process_response = chfi->process_response;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	count = snprintf(buf, buf_sz, "<ecm_classifier_hyfi>\n");
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
	count = snprintf(buf + total, buf_sz, "</ecm_classifier_hyfi>\n");
	if ((count <= 0) || (count >= buf_sz)) {
		return -1;
	}
	total += count;
	return total;
}

/*
 * ecm_classifier_hyfi_instance_alloc()
 *	Allocate an instance of the HyFi classifier
 */
struct ecm_classifier_hyfi_instance *ecm_classifier_hyfi_instance_alloc(struct ecm_db_connection_instance *ci)
{
	struct ecm_classifier_hyfi_instance *chfi;

	/*
	 * Allocate the instance
	 */
	chfi = (struct ecm_classifier_hyfi_instance *)kzalloc(sizeof(struct ecm_classifier_hyfi_instance), GFP_ATOMIC | __GFP_NOWARN);
	if (!chfi) {
		DEBUG_WARN("Failed to allocate HyFi instance\n");
		return NULL;
	}

	DEBUG_SET_MAGIC(chfi, ECM_CLASSIFIER_HYFI_INSTANCE_MAGIC);
	chfi->refs = 1;
	chfi->base.process = ecm_classifier_hyfi_process;
	chfi->base.sync_from_v4 = ecm_classifier_hyfi_sync_from_v4;
	chfi->base.sync_to_v4 = ecm_classifier_hyfi_sync_to_v4;
	chfi->base.sync_from_v6 = ecm_classifier_hyfi_sync_from_v6;
	chfi->base.sync_to_v6 = ecm_classifier_hyfi_sync_to_v6;
	chfi->base.type_get = ecm_classifier_hyfi_type_get;
	chfi->base.last_process_response_get = ecm_classifier_hyfi_last_process_response_get;
	chfi->base.reclassify_allowed = ecm_classifier_hyfi_reclassify_allowed;
	chfi->base.reclassify = ecm_classifier_hyfi_reclassify;
	chfi->base.xml_state_get = ecm_classifier_hyfi_xml_state_get;
	chfi->base.ref = ecm_classifier_hyfi_ref;
	chfi->base.deref = ecm_classifier_hyfi_deref;
	chfi->ci_serial = ecm_db_connection_serial_get(ci);
	chfi->process_response.process_actions = 0;
	chfi->process_response.relevance = ECM_CLASSIFIER_RELEVANCE_MAYBE;

	/*
	 * Init Hy-Fi state
	 */
	chfi->hyfi_state = ECM_CLASSIFIER_HYFI_STATE_INIT;

	spin_lock_bh(&ecm_classifier_hyfi_lock);

	/*
	 * Final check if we are pending termination
	 */
	if (ecm_classifier_hyfi_terminate_pending) {
		spin_unlock_bh(&ecm_classifier_hyfi_lock);
		DEBUG_INFO("%p: Terminating\n", ci);
		kfree(chfi);
		return NULL;
	}

	/*
	 * Link the new instance into our list at the head
	 */
	chfi->next = ecm_classifier_hyfi_instances;
	if (ecm_classifier_hyfi_instances) {
		ecm_classifier_hyfi_instances->prev = chfi;
	}
	ecm_classifier_hyfi_instances = chfi;

	/*
	 * Increment stats
	 */
	ecm_classifier_hyfi_count++;
	DEBUG_ASSERT(ecm_classifier_hyfi_count > 0, "%p: ecm_classifier_hyfi_count wrap\n", chfi);
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	DEBUG_INFO("HyFi instance alloc: %p\n", chfi);
	return chfi;
}
EXPORT_SYMBOL(ecm_classifier_hyfi_instance_alloc);

/*
 * ecm_classifier_hyfi_connection_added()
 *	Invoked when a connection is added to the DB
 */
static void ecm_classifier_hyfi_connection_added(void *arg, struct ecm_db_connection_instance *ci)
{
#if (DEBUG_LEVEL > 2)
	uint32_t serial = ecm_db_connection_serial_get(ci);
	DEBUG_INFO("%p: HYFI LISTENER: added conn with serial: %u\n", ci, serial);
#endif
//	Add your own code here
}

/*
 * ecm_classifier_hyfi_connection_removed()
 *	Invoked when a connection is removed from the DB
 */
static void ecm_classifier_hyfi_connection_removed(void *arg, struct ecm_db_connection_instance *ci)
{
#if (DEBUG_LEVEL > 2)
	uint32_t serial = ecm_db_connection_serial_get(ci);
	DEBUG_INFO("%p: HYFI LISTENER: removed conn with serial: %u\n", ci, serial);
#endif
//	Add your own code here
}

/*
 * ecm_classifier_hyfi_set_set_command()
 *	Set hyfi command to accel/decel connection.
 */
static ssize_t ecm_classifier_hyfi_set_command(struct device *dev,
							  struct device_attribute *attr,
							  const char *buf, size_t count)
{
#define ECM_CLASSIFIER_HYFI_SET_IP_COMMAND_FIELDS 2
	char *cmd_buf;
	int field_count;
	char *field_ptr;
	char *fields[ECM_CLASSIFIER_HYFI_SET_IP_COMMAND_FIELDS];
	char cmd;
	uint32_t serial;
	struct ecm_db_connection_instance *ci;
	struct ecm_front_end_connection_instance *feci;

	/*
	 * Check if we are enabled
	 */
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	if (!ecm_classifier_hyfi_enabled) {
		spin_unlock_bh(&ecm_classifier_hyfi_lock);
		return 0;
	}
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	/*
	 * buf is formed as:
	 * [0]   [1]
	 * <CMD>/<SERIAL>
	 * CMD:
	 *	s = Decelerate based on <SERIAL> number given.
	 */
	cmd_buf = (char *)kzalloc(count + 1, GFP_ATOMIC);
	if (!cmd_buf) {
		return 0;
	}
	memcpy(cmd_buf, buf, count);

	/*
	 * Split the buffer into its fields
	 */
	field_count = 0;
	field_ptr = cmd_buf;
	fields[field_count] = strsep(&field_ptr, "/");
	while (fields[field_count] != NULL) {
		DEBUG_TRACE("FIELD %d: %s\n", field_count, fields[field_count]);
		field_count++;
		if (field_count == ECM_CLASSIFIER_HYFI_SET_IP_COMMAND_FIELDS) {
			break;
		}
		fields[field_count] = strsep(&field_ptr, "/");
	}

	if (field_count != ECM_CLASSIFIER_HYFI_SET_IP_COMMAND_FIELDS) {
		DEBUG_WARN("invalid field count %d\n", field_count);
		kfree(cmd_buf);
		return 0;
	}

	if (!sscanf(fields[0], "%c", &cmd)) {
		DEBUG_WARN("invalid cmd\n");
		kfree(cmd_buf);
		return 0;
	}
	if (!sscanf(fields[1], "%u", &serial)) {
		DEBUG_WARN("invalid serial\n");
		kfree(cmd_buf);
		return 0;
	}

	kfree(cmd_buf);

	/*
	 * Locate the connection using the serial or tuple given
	 */
	switch (cmd) {
	case 's':
		DEBUG_TRACE("Lookup connection using serial: %u\n", serial);
		ci = ecm_db_connection_serial_find_and_ref(serial);
		break;
	default:
		DEBUG_WARN("invalid cmd %c\n", cmd);
		return 0;
	}

	if (!ci) {
		DEBUG_WARN("database connection not found\n");
		return 0;
	}
	DEBUG_TRACE("Connection found: %p\n", ci);

	/*
	 * Now action the command
	 */
	switch (cmd) {
	case 's':
	case 'f':
		/*
		 * Decelerate the connection
		 */
		DEBUG_TRACE("Force decel: %p\n", ci);
		feci = ecm_db_connection_front_end_get_and_ref(ci);
		feci->decelerate(feci);
		feci->deref(feci);
		break;
	}
	ecm_db_connection_deref(ci);

	return count;
}

/*
 * ecm_classifier_hyfi_rule_get_enabled()
 */
static ssize_t ecm_classifier_hyfi_rule_get_enabled(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	ssize_t count;
	int num;

	/*
	 * Operate under our locks
	 */
	DEBUG_TRACE("get enabled\n");
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	num = ecm_classifier_hyfi_enabled;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	count = snprintf(buf, (ssize_t)PAGE_SIZE, "%d\n", num);
	return count;
}

/*
 * ecm_classifier_hyfi_rule_set_enabled()
 */
static ssize_t ecm_classifier_hyfi_rule_set_enabled(struct device *dev,
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
	DEBUG_TRACE("ecm_classifier_hyfi_enabled = %d\n", num);

	/*
	 * Operate under our locks
	 */
	spin_lock_bh(&ecm_classifier_hyfi_lock);
	ecm_classifier_hyfi_enabled = num;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	return count;
}

/*
 * System device attributes for the hyfi classifier itself.
 */
static DEVICE_ATTR(enabled, 0644, ecm_classifier_hyfi_rule_get_enabled, ecm_classifier_hyfi_rule_set_enabled);
static DEVICE_ATTR(cmd, 0200, NULL, ecm_classifier_hyfi_set_command);

/*
 * System device attribute array.
 */
static struct device_attribute *ecm_classifier_hyfi_attrs[] = {
	&dev_attr_enabled,
	&dev_attr_cmd,
};

/*
 * System device node of the ECM hyfi classifier
 * Sysdevice control points can be found at /sys/devices/system/ecm_classifier_hyfi/ecm_classifier_hyfiX/
 */
static struct bus_type ecm_classifier_hyfi_subsys = {
	.name = "ecm_classifier_hyfi",
	.dev_name = "ecm_classifier_hyfi",
};

/*
 * ecm_classifier_hyfi_dev_release()
 *	This is a dummy release function for device.
 */
static void ecm_classifier_hyfi_dev_release(struct device *dev)
{

}

/*
 * ecm_classifier_hyfi_rules_init()
 */
int ecm_classifier_hyfi_rules_init(void)
{
	int result;
	int i;
	DEBUG_INFO("HyFi classifier Module init\n");

	/*
	 * Initialise our global lock
	 */
	spin_lock_init(&ecm_classifier_hyfi_lock);

	/*
	 * Register the Sub system
	 */
	result = subsys_system_register(&ecm_classifier_hyfi_subsys, NULL);
	if (result) {
		DEBUG_ERROR("Failed to register sub system %d\n", result);
		return result;
	}

	/*
	 * Register System device control
	 */
	memset(&ecm_classifier_hyfi_dev, 0, sizeof(ecm_classifier_hyfi_dev));
	ecm_classifier_hyfi_dev.id = 0;
	ecm_classifier_hyfi_dev.bus = &ecm_classifier_hyfi_subsys;
	ecm_classifier_hyfi_dev.release = &ecm_classifier_hyfi_dev_release;
	result = device_register(&ecm_classifier_hyfi_dev);
	if (result) {
		DEBUG_ERROR("Failed to register System device %d\n", result);
		goto classifier_task_cleanup_1;
	}

	/*
	 * Create files, one for each parameter supported by this module
	 */
	for (i = 0; i < ARRAY_SIZE(ecm_classifier_hyfi_attrs); i++) {
		result = device_create_file(&ecm_classifier_hyfi_dev, ecm_classifier_hyfi_attrs[i]);
		if (result) {
			DEBUG_ERROR("Failed to register system device file %d\n", result);
			goto classifier_task_cleanup_2;
		}
	}

	/*
	 * Allocate listener instance to listen for db events
	 */
	ecm_classifier_hyfi_li = ecm_db_listener_alloc();
	if (!ecm_classifier_hyfi_li) {
		DEBUG_ERROR("Failed to allocate listener\n");
		goto classifier_task_cleanup_2;
	}

	/*
	 * Add the listener into the database
	 * NOTE: Ref the thread count for the listener
	 */
	ecm_db_listener_add(ecm_classifier_hyfi_li,
			NULL /* ecm_classifier_hyfi_iface_added */,
			NULL /* ecm_classifier_hyfi_iface_removed */,
			NULL /* ecm_classifier_hyfi_node_added */,
			NULL /* ecm_classifier_hyfi_node_removed */,
			NULL /* ecm_classifier_hyfi_host_added */,
			NULL /* ecm_classifier_hyfi_host_removed */,
			NULL /* ecm_classifier_hyfi_mapping_added */,
			NULL /* ecm_classifier_hyfi_mapping_removed */,
			ecm_classifier_hyfi_connection_added,
			ecm_classifier_hyfi_connection_removed,
			NULL /* ecm_classifier_hyfi_listener_final */,
			ecm_classifier_hyfi_li);

	return 0;

classifier_task_cleanup_2:
	while (--i >= 0) {
		device_remove_file(&ecm_classifier_hyfi_dev, ecm_classifier_hyfi_attrs[i]);
	}
	device_unregister(&ecm_classifier_hyfi_dev);
classifier_task_cleanup_1:
	bus_unregister(&ecm_classifier_hyfi_subsys);

	return result;
}
EXPORT_SYMBOL(ecm_classifier_hyfi_rules_init);

/*
 * ecm_classifier_hyfi_rules_exit()
 */
void ecm_classifier_hyfi_rules_exit(void)
{
	int i;
	DEBUG_INFO("HyFi classifier Module exit\n");

	spin_lock_bh(&ecm_classifier_hyfi_lock);
	ecm_classifier_hyfi_terminate_pending = true;
	spin_unlock_bh(&ecm_classifier_hyfi_lock);

	/*
	 * Release our ref to the listener.
	 * This will cause it to be unattached to the db listener list.
	 * NOTE: Our thread refs will be released on final callback when
	 * we know there will be no more callbacks to it.
	 */
	if (ecm_classifier_hyfi_li) {
		ecm_db_listener_deref(ecm_classifier_hyfi_li);
		ecm_classifier_hyfi_li = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(ecm_classifier_hyfi_attrs); i++) {
		device_remove_file(&ecm_classifier_hyfi_dev, ecm_classifier_hyfi_attrs[i]);
	}

	device_unregister(&ecm_classifier_hyfi_dev);
	bus_unregister(&ecm_classifier_hyfi_subsys);
}
EXPORT_SYMBOL(ecm_classifier_hyfi_rules_exit);
