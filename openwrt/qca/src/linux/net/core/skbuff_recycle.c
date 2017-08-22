/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 *      Generic skb recycler
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <skbuff_recycle.h>
#include <trace/events/skb.h>

static DEFINE_PER_CPU(struct sk_buff_head, recycle_list);
#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
static DEFINE_PER_CPU(struct sk_buff_head, recycle_spare_list);
static struct global_recycler glob_recycler;
#endif


inline struct sk_buff *skb_recycler_alloc(struct net_device *dev, unsigned int length) {
	unsigned long flags;
	struct sk_buff_head *h;
	struct sk_buff *skb = NULL;

	if (unlikely(length > SKB_RECYCLE_SIZE)) {
		return NULL;
	}

	h = &get_cpu_var(recycle_list);
	local_irq_save(flags);
	skb = __skb_dequeue(h);
#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
	if (unlikely(!skb)) {
		uint8_t head;
		spin_lock(&glob_recycler.lock);
		/* If global recycle list is not empty, use global buffers */
		head = glob_recycler.head;
		if (likely(head != glob_recycler.tail)) {
			/* Move SKBs from global list to CPU pool */
			skb_queue_splice_init(&glob_recycler.pool[head], h);
			head = (head + 1) & SKB_RECYCLE_MAX_SHARED_POOLS_MASK;
			glob_recycler.head = head;
			spin_unlock(&glob_recycler.lock);
			/* We have refilled the CPU pool - dequeue */
			skb = __skb_dequeue(h);
		} else {
			spin_unlock(&glob_recycler.lock);
		}
	}
#endif
	local_irq_restore(flags);
	put_cpu_var(recycle_list);

	if (likely(skb)) {
		struct skb_shared_info *shinfo;

		/*
		 * We're about to write a large amount to the skb to
		 * zero most of the structure so prefetch the start
		 * of the shinfo region now so it's in the D-cache
		 * before we start to write that.
		 */
		shinfo = skb_shinfo(skb);
		prefetchw(shinfo);

		zero_struct(skb, offsetof(struct sk_buff, tail));
#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb->mac_header = ~0U;
#endif
		zero_struct(shinfo, offsetof(struct skb_shared_info, dataref));
		atomic_set(&shinfo->dataref, 1);

		skb->data = skb->head + NET_SKB_PAD;
		skb_reset_tail_pointer(skb);

		if (dev) {
			skb->dev = dev;
		}
	}

	return skb;
}

inline bool skb_recycler_consume(struct sk_buff *skb) {
	unsigned long flags;
	struct sk_buff_head *h;

	/* Can we recycle this skb?  If not, simply return that we cannot */
	if (unlikely(!consume_skb_can_recycle(skb, SKB_RECYCLE_MIN_SIZE,
					      SKB_RECYCLE_MAX_SIZE)))
		return false;

	/*
	 * If we can, then it will be much faster for us to recycle this one
	 * later than to allocate a new one from scratch.
	 */
	preempt_disable();
	h = &__get_cpu_var(recycle_list);
	local_irq_save(flags);
	/* Attempt to enqueue the CPU hot recycle list first */
	if (likely(skb_queue_len(h) < SKB_RECYCLE_MAX_SKBS)) {
		__skb_queue_head(h, skb);
		local_irq_restore(flags);
		preempt_enable();
		return true;
	}
#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
	h = &__get_cpu_var(recycle_spare_list);

	/* The CPU hot recycle list was full; if the spare list is also full,
	 * attempt to move the spare list to the global list for other CPUs to
	 * use.
	 */
	if (unlikely(skb_queue_len(h) >= SKB_RECYCLE_SPARE_MAX_SKBS)) {
		uint8_t cur_tail, next_tail;
		spin_lock(&glob_recycler.lock);
		cur_tail = glob_recycler.tail;
		next_tail = (cur_tail + 1) & SKB_RECYCLE_MAX_SHARED_POOLS_MASK;
		if (next_tail != glob_recycler.head) {
			struct sk_buff_head *p = &glob_recycler.pool[cur_tail];

			/* Optimized, inlined SKB List splice */
			p->next = h->next;
			h->next->prev = (struct sk_buff *)p;
			p->prev = h->prev;
			h->prev->next = (struct sk_buff *)p;
			p->qlen = SKB_RECYCLE_SPARE_MAX_SKBS;

			/* Done with global list init */
			glob_recycler.tail = next_tail;
			spin_unlock(&glob_recycler.lock);

			/*
			 * We have now cleared room in the spare;
			 * Intialize and enqueue skb into spare
			 */
			skb->next = skb->prev = (struct sk_buff *)h;
			h->prev = h->next = skb;
			h->qlen = 1;

			local_irq_restore(flags);
			preempt_enable();
			return true;
		}
		/* We still have a full spare because the global is also full */
		spin_unlock(&glob_recycler.lock);
	} else {
		/* We have room in the spare list; enqueue to spare list */
		__skb_queue_head(h, skb);
		local_irq_restore(flags);
		preempt_enable();
		return true;
	}
#endif

	local_irq_restore(flags);
	preempt_enable();

	return false;
}

static void skb_recycler_free_skb(struct sk_buff_head *list)
{
	struct sk_buff *skb = NULL;

	while ((skb = skb_dequeue(list)) != NULL) {
		trace_consume_skb(skb);
		skb_release_data(skb);
		kfree_skbmem(skb);
	}
}

static int skb_cpu_callback(struct notifier_block *nfb,
		unsigned long action, void *ocpu)
{
	unsigned long oldcpu = (unsigned long)ocpu;

	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		skb_recycler_free_skb(&per_cpu(recycle_list, oldcpu));
#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
		skb_recycler_free_skb(&per_cpu(recycle_spare_list, oldcpu));
#endif
	}

	return NOTIFY_OK;
}


void __init skb_recycler_init() {
	int cpu;

	for_each_possible_cpu(cpu) {
		skb_queue_head_init(&per_cpu(recycle_list, cpu));
	}

#ifdef CONFIG_SKB_RECYCLER_MULTI_CPU
	for_each_possible_cpu(cpu) {
		skb_queue_head_init(&per_cpu(recycle_spare_list, cpu));
	}

	spin_lock_init(&glob_recycler.lock);
	{
		unsigned int i;
		for (i = 0; i < SKB_RECYCLE_MAX_SHARED_POOLS; i++) {
			skb_queue_head_init(&glob_recycler.pool[i]);
		}
		glob_recycler.head = 0;
		glob_recycler.tail = 0;
	}
#endif

	hotcpu_notifier(skb_cpu_callback, 0);
}
