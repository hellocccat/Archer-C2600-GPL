/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 *      Definitions for the skb recycler functions
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_SKBUFF_RECYCLE_H
#define _LINUX_SKBUFF_RECYCLE_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/kmemcheck.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#ifdef CONFIG_NET_CLS_ACT
#include <net/pkt_sched.h>
#endif
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/splice.h>
#include <linux/init.h>
#include <linux/prefetch.h>
#include <linux/if.h>



#define SKB_RECYCLE_SIZE	2304
#define SKB_RECYCLE_MIN_SIZE	SKB_RECYCLE_SIZE
#define SKB_RECYCLE_MAX_SIZE	(3904 - NET_SKB_PAD)
#define SKB_RECYCLE_MAX_SKBS	1024

#define SKB_RECYCLE_SPARE_MAX_SKBS		256
#define SKB_RECYCLE_MAX_SHARED_POOLS		8
#define SKB_RECYCLE_MAX_SHARED_POOLS_MASK	(SKB_RECYCLE_MAX_SHARED_POOLS - 1)

#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
struct global_recycler {
	/* Global circular list which holds the shared skb pools */
	struct sk_buff_head pool[SKB_RECYCLE_MAX_SHARED_POOLS];
	uint8_t head;		/* head of the circular list */
	uint8_t tail;		/* tail of the circular list */
	spinlock_t lock;
};
#endif

static inline void zero_struct(void *v, int size)
{
	uint32_t *s = (uint32_t *)v;

	/* We assume that size is word aligned; in fact, it's constant */
	BUG_ON((size & 3) != 0);

	/*
	 * This looks odd but we "know" size is a constant, and so the
	 * compiler can fold away all of the conditionals.  The compiler is
	 * pretty smart here, and can fold away the loop, too!
	 */
	while (size > 0) {
		if (size >= 4)
			s[0] = 0;
		if (size >= 8)
			s[1] = 0;
		if (size >= 12)
			s[2] = 0;
		if (size >= 16)
			s[3] = 0;
		if (size >= 20)
			s[4] = 0;
		if (size >= 24)
			s[5] = 0;
		if (size >= 28)
			s[6] = 0;
		if (size >= 32)
			s[7] = 0;
		if (size >= 36)
			s[8] = 0;
		if (size >= 40)
			s[9] = 0;
		if (size >= 44)
			s[10] = 0;
		if (size >= 48)
			s[11] = 0;
		if (size >= 52)
			s[12] = 0;
		if (size >= 56)
			s[13] = 0;
		if (size >= 60)
			s[14] = 0;
		if (size >= 64)
			s[15] = 0;
		size -= 64;
		s += 16;
	}
}

static inline bool consume_skb_can_recycle(const struct sk_buff *skb,
					   int min_skb_size, int max_skb_size)
{
	if (unlikely(irqs_disabled()))
		return false;

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_DEV_ZEROCOPY))
		return false;

	if (unlikely(skb_is_nonlinear(skb)))
		return false;

	if (unlikely(skb->fclone != SKB_FCLONE_UNAVAILABLE))
		return false;

	min_skb_size = SKB_DATA_ALIGN(min_skb_size + NET_SKB_PAD);
	if (unlikely(skb_end_pointer(skb) - skb->head < min_skb_size))
		return false;

	max_skb_size = SKB_DATA_ALIGN(max_skb_size + NET_SKB_PAD);
	if (unlikely(skb_end_pointer(skb) - skb->head > max_skb_size))
		return false;

	if (unlikely(skb_cloned(skb)))
		return false;

	return true;
}

#ifdef CONFIG_SKB_RECYCLER

void __init skb_recycler_init(void);
struct sk_buff *skb_recycler_alloc(struct net_device *dev, unsigned int length);
bool skb_recycler_consume(struct sk_buff *skb);

#else

#define skb_recycler_init()  {}
#define skb_recycler_alloc(dev, len) NULL
#define skb_recycler_consume(skb) false

#endif
#endif
