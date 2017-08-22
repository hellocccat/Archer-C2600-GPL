/*
 *  QCA Hy-Fi ECM
 *
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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
#include <linux/export.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include "hyfi_hash.h"
#include "hyfi_hatbl.h"
#include "hyfi_ecm.h"

/*
 * Notify about a new connection
 * returns:
 * -1: error
 * 0: okay
 * 1: not interested
 * 2: hy-fi not attached
 */

static int hyfi_ecm_new_connection(struct hyfi_net_bridge *hyfi_br, const struct hyfi_ecm_flow_data_t *flow)
{
	u_int32_t traffic_class;
	struct net_hatbl_entry *ha = NULL;

	traffic_class = (flow->flag & IS_IPPROTO_UDP) ?
			HYFI_TRAFFIC_CLASS_UDP : HYFI_TRAFFIC_CLASS_OTHER;

	spin_lock_bh(&hyfi_br->hash_ha_lock);

	/* Find H-Active entry */
	ha = hatbl_find(hyfi_br, flow->hash, flow->da,
				traffic_class, flow->priority);

	if (ha) {
		/* Found. Update ecm serial number and return */
		ha->ecm_serial = flow->ecm_serial;
		spin_unlock_bh(&hyfi_br->hash_ha_lock);
#if 0
		printk("hyfi: New accelerated connection with serial number: %d, hash: 0x%02x\n",
				flow->ecm_serial, flow->hash);
#endif
		return 0;

	} else {
		/* H-Active was not found, look for H-Default entry, and create an
		 * H-Active entry if exists.
		 */
		struct net_hdtbl_entry *hd;

		/* Unlock the ha-lock, and lock the hd-lock */
		spin_unlock_bh(&hyfi_br->hash_ha_lock);

		spin_lock_bh(&hyfi_br->hash_hd_lock);
		hd = hyfi_hdtbl_find(hyfi_br, flow->da);

		if (hd) {
			/* Create a new entry based on H-Default table. The function
			 * will keep the ha-lock if created successfully. */
			ha = hyfi_hatbl_insert_ecm_classifier(hyfi_br, flow->hash,
					traffic_class, hd, flow->priority,
					flow->sa, flow->ecm_serial);

			/* Release the hd-lock, we are done with the hd entry */
			spin_unlock_bh(&hyfi_br->hash_hd_lock);

			if(ha) {
				/* H-Active created. */
				spin_unlock_bh(&hyfi_br->hash_ha_lock);
#if 0
				printk("hyfi: New accelerated connection from HD with serial number: %d, hash: 0x%02x",
						flow->ecm_serial, flow->hash);
#endif
				return 0;
			}
		} else {
#if 0
			printk("hyfi: no hd to %02X:%02X:%02X:%02X:%02X:%02X\n", flow->da[0],
					flow->da[1], flow->da[2], flow->da[3],
					flow->da[4], flow->da[5] );
#endif
			/* No such H-Default entry, unlock hd-lock */
			spin_unlock_bh(&hyfi_br->hash_hd_lock);
			return 1;
		}
	}

	return 0;
}

int hyfi_ecm_update_stats(const struct hyfi_ecm_flow_data_t *flow, u_int64_t num_bytes, u_int64_t num_packets)
{
	struct net_hatbl_entry *ha = NULL;
	struct hyfi_net_bridge *hyfi_br;
	int ret = 0;

	if(!num_bytes || !num_packets)
		return 0;

	if(!flow)
		return -1;

	hyfi_br = hyfi_bridge_get(HYFI_BRIDGE_ME);

	if(!hyfi_br) {
		/* Hy-Fi bridge not attached */
		return 2;
	}

	spin_lock_bh(&hyfi_br->hash_ha_lock);

	/* Find H-Active entry */
	if (flow->ecm_serial != ~0 && (ha = hatbl_find_ecm(hyfi_br, flow->hash, flow->ecm_serial))) {
		if (!hyfi_ha_has_flag(ha, HYFI_HACTIVE_TBL_ACCL_ENTRY)) {

			/* This flow is now accelerated */
			hyfi_ha_set_flag(ha, HYFI_HACTIVE_TBL_ACCL_ENTRY);
			ha->prev_num_packets = num_packets;
			ha->prev_num_bytes = num_bytes;

			/* Flush seamless buffer - does not apply for accelerate flows */
			if (hyfi_ha_has_flag(ha, HYFI_HACTIVE_TBL_SEAMLESS_ENABLED)) {
				hyfi_ha_clear_flag(ha, HYFI_HACTIVE_TBL_SEAMLESS_ENABLED);
				hyfi_psw_flush_track_q(&ha->psw_stm_entry);
			}
		}

		ha->num_bytes += num_bytes - ha->prev_num_bytes;
		ha->num_packets += num_packets - ha->prev_num_packets;
		ha->prev_num_bytes = num_bytes;
		ha->prev_num_packets = num_packets;

		spin_unlock_bh(&hyfi_br->hash_ha_lock);
#if 0
		printk("hyfi: Updated stats for hash 0x%02x, serial=%d, num_bytes=%d, num_packets=%d\n",
				flow->hash, flow->ecm_serial, ha->num_bytes, ha->num_packets);
#endif
		return 0;
	}

	spin_unlock_bh(&hyfi_br->hash_ha_lock);

	ret = hyfi_ecm_new_connection(hyfi_br, flow);
	return ret;
}

EXPORT_SYMBOL(hyfi_ecm_update_stats);
