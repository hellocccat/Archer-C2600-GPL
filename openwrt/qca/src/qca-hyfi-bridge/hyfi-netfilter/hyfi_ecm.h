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

#ifndef HYFI_ECM_H_
#define HYFI_ECM_H_

#include <linux/skbuff.h>
#include <linux/types.h>

struct hyfi_ecm_flow_data_t {
	u_int32_t ecm_serial;
	u_int32_t hash;
	u_int32_t flag;
	u_int32_t priority;
	u_int16_t seq;
	u_int8_t da[6];
	u_int8_t sa[6];
};

/*
 * Periodic stats updates
 * returns:
 * -1: error
 * 0: okay
 * 1: not interested
 * 2: hy-fi not attached
 */
int hyfi_ecm_update_stats(const struct hyfi_ecm_flow_data_t *flow, u_int64_t num_bytes, u_int64_t num_packets);

#endif /* HYFI_ECM_H_ */
