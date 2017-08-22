/*
 * Copyright (c) 2012, 2015, The Linux Foundation. All rights reserved.
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
 */


#ifdef KVER32
#include <linux/kconfig.h>
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#include <linux/kthread.h>
#include <linux/udp.h>
#include <linux/rculist_nulls.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include "../nat_helper.h"
#include "../napt_helper.h"

#include "nat_helper_dt.h"
#include "nat_helper_hsl.h"
#include "fal_type.h"
#include "fal_nat.h"

extern int nat_sockopts_init;
extern uint32_t napt_set_default_route(fal_ip4_addr_t dst_addr, fal_ip4_addr_t src_addr);
extern uint32_t napt_set_ipv6_default_route(void);
extern void nat_ipt_sockopts_replace(void);

#define NAPT_BUFFER_HASH_SIZE        (NAPT_TABLE_SIZE)
#define NAPT_BUFFER_SIZE             ((NAPT_BUFFER_HASH_SIZE)*8)

struct napt_ct
{
    struct napt_ct *next;
    a_uint32_t ct_addr;
    a_uint64_t ct_packets;
    a_uint8_t in_hw;
    a_uint16_t hw_index;
    a_uint8_t deny;
};

struct nhlist_head
{
    struct napt_ct *next;
};

static struct nhlist_head *ct_buf_hash_head = NULL;
static struct napt_ct *ct_buf = NULL;
static a_uint32_t ct_buf_ct_cnt = 0;

static a_int32_t
napt_hash_buf_init(struct napt_ct **hash, struct nhlist_head **hash_head)
{
    a_uint32_t hash_size = NAPT_BUFFER_HASH_SIZE;
    a_uint32_t buffer_size = NAPT_BUFFER_SIZE;

    *hash = (struct napt_ct *)kmalloc(sizeof(struct napt_ct)*buffer_size, GFP_ATOMIC);
    if(!(*hash))
    {
        HNAT_PRINTK("NAPT INIT ERROR! No Sufficient Memory!");
        return -1;
    }

    *hash_head = (struct nhlist_head *)kmalloc(sizeof(struct nhlist_head)*hash_size, GFP_ATOMIC);
    if(!(*hash_head))
    {
        HNAT_PRINTK("NAPT INIT ERROR! No Sufficient Memory!");
        kfree(*hash);
        return -1;
    }

    memset(*hash,0,sizeof(struct napt_ct)*buffer_size);
    memset(*hash_head,0,sizeof(struct nhlist_head)*hash_size);

    return 0;
}

#define NAPT_CT_HASH(ct_addr) (((ct_addr) * (0x9e370001UL)) >> 22)

static struct napt_ct *
napt_hash_add(a_uint32_t ct_addr, a_uint32_t *hash_cnt,
              struct napt_ct *hash, struct nhlist_head *hash_head)
{
    struct napt_ct *entry = 0,*last = 0,*node = 0;
    struct nhlist_head *head = 0;
    a_uint32_t hash_index = NAPT_CT_HASH(ct_addr);

    if(*hash_cnt >= NAPT_BUFFER_SIZE)
    {
        return NULL;
    }
    head = &(hash_head[hash_index]);
    entry = head->next;

    while(entry)
    {
        if(ct_addr == entry->ct_addr)
        {
            return entry;
        }
        else
        {
            last = entry;
            entry = entry->next;
        }
    }

    node = &(hash[*hash_cnt]);
    node->ct_addr = ct_addr;
    node->ct_packets = 0;
    node->in_hw = 0;
    node->hw_index = 0;
    node->deny = 0;

    if(head->next == 0)
    {
        head->next = node;
    }
    else
    {
        last->next = node;
    }
    (*hash_cnt)++;

    return node;
}

static struct napt_ct *
napt_hash_find(a_uint32_t ct_addr, a_uint32_t *hash_cnt,
               struct napt_ct *hash, struct nhlist_head *hash_head)
{
    struct napt_ct *entry = 0;
    struct nhlist_head *head = 0;
    a_uint32_t hash_index = NAPT_CT_HASH(ct_addr);

    if(*hash_cnt == 0)
    {
        return NULL;
    }
#if 0 /* prevent empty entries. */
    if(*hash_cnt >= NAPT_BUFFER_SIZE)
    {
        return NULL;
    }
#endif

    head = &(hash_head[hash_index]);

    if(head->next == 0)
    {
        return NULL;
    }
    entry = head->next;
    do
    {
        if(ct_addr == entry->ct_addr)
        {
            return entry;
        }

        entry = entry->next;
    }
    while(entry);

    return NULL;
}

static a_int32_t
napt_ct_buf_init(void)
{
    return napt_hash_buf_init(&ct_buf, &ct_buf_hash_head);
}

static void
napt_ct_buf_exit(void)
{
    if(ct_buf_hash_head)
        kfree(ct_buf_hash_head);

    if(ct_buf)
        kfree(ct_buf);
}

static void
napt_ct_buf_flush(void)
{
    ct_buf_ct_cnt = 0;
    memset(ct_buf,0,sizeof(struct napt_ct)*NAPT_BUFFER_SIZE);
    memset(ct_buf_hash_head,0,sizeof(struct nhlist_head)*NAPT_BUFFER_HASH_SIZE);
}

static a_uint32_t
napt_ct_cnt_get(void)
{
    return ct_buf_ct_cnt;
}

static struct napt_ct *
napt_ct_buf_ct_find(a_uint32_t ct_addr)
{
    return napt_hash_find(ct_addr, &ct_buf_ct_cnt,
                          ct_buf, ct_buf_hash_head);
}

static a_uint64_t
napt_ct_buf_pkts_get(struct napt_ct *napt_ct)
{
    return napt_ct->ct_packets;
}

static void
napt_ct_buf_pkts_update(struct napt_ct *napt_ct, a_uint64_t packets)
{
    napt_ct->ct_packets = packets;
}

static a_uint8_t
napt_ct_buf_deny_get(struct napt_ct *napt_ct)
{
    return napt_ct->deny;
}

static void
napt_ct_buf_deny_set(struct napt_ct *napt_ct, a_uint8_t deny)
{
    napt_ct->deny = deny;
}

static void
napt_ct_buf_deny_clear(struct napt_ct *napt_ct)
{
    napt_ct->deny = 0;
}

static a_uint8_t
napt_ct_buf_in_hw_get(struct napt_ct *napt_ct, a_uint16_t *hw_index)
{
    *hw_index = napt_ct->hw_index;
    return napt_ct->in_hw;
}

static void
napt_ct_buf_in_hw_set(struct napt_ct *napt_ct, a_uint16_t hw_index)
{
    napt_ct->in_hw = 1;
    napt_ct->hw_index = hw_index;
}

static void
napt_ct_buf_in_hw_clear(struct napt_ct *napt_ct)
{
    napt_ct->in_hw = 0;
    napt_ct->hw_index = 0;
}

static void
napt_ct_buf_ct_info_clear(struct napt_ct *napt_ct)
{
    napt_ct->ct_addr = 0;
    napt_ct->ct_packets = 0;
}

static struct napt_ct *
napt_ct_buf_ct_add(a_uint32_t ct_addr)
{
    struct napt_ct *napt_ct;
    napt_ct = napt_hash_add(ct_addr, &ct_buf_ct_cnt,
                            ct_buf, ct_buf_hash_head);

    if(napt_ct)
    {
        /*ct pkts initial*/
        napt_ct_buf_pkts_update(napt_ct, NAPT_CT_PKTS_GET(ct_addr));
    }

    return napt_ct;
}

#define NAPT_CT_PERMANENT_DENY 5
static a_uint32_t napt_ct_addr[NAPT_TABLE_SIZE] = {0};

#define NAPT_CT_PACKET_THRES_BASE    (50)
static a_uint64_t packets_bdir_total = 0;
static a_uint64_t packets_bdir_thres = 0;

static inline a_int32_t
before(a_uint64_t seq1, a_uint64_t seq2)
{
    return ((int64_t)(seq1-seq2) < 0);
}

static a_uint8_t
napt_ct_pkts_reach_thres(a_uint32_t ct_addr, struct napt_ct *napt_ct,
                         a_uint8_t pkts_sum)
{
    a_uint64_t packets_bdir_old = napt_ct_buf_pkts_get(napt_ct);
    a_uint64_t packets_bdir_new = NAPT_CT_PKTS_GET(ct_addr);

    if(pkts_sum)
    {
        if(packets_bdir_new > packets_bdir_old)
        {
            packets_bdir_total += (packets_bdir_new - packets_bdir_old);
        }
    }

    napt_ct_buf_pkts_update(napt_ct, packets_bdir_new);

    HNAT_PRINTK("<%s> ct:%x packets_bdir_old:%lld ==> packets_bdir_new:%lld\n",
                __func__, ct_addr, packets_bdir_old, packets_bdir_new);

    if(before((packets_bdir_old+packets_bdir_thres), packets_bdir_new))
    {
        return 1;
    }

    return 0;
}

static a_int32_t
napt_ct_hw_add(a_uint32_t ct_addr, a_uint16_t *hw_index)
{
    napt_entry_t napt = {0};
    a_uint32_t index;

    if (!ct_addr)
        return -1;

    NAPT_CT_TO_HW_ENTRY(ct_addr, &napt);

    if(nat_hw_pub_ip_add(napt.trans_addr, &index) == 0)
    {
        napt.trans_addr = index;

    }
    else
    {
        HNAT_ERR_PRINTK("####%s##nat_hw_pub_ip_add fail!\n", __func__);
        return -1;
    }

    sw_error_t rv = napt_hw_add(&napt);

    if(rv == 0)
    {
        HNAT_PRINTK("%s: success entry_id:0x%x ct 0x%x\n", __func__, napt.entry_id, ct_addr);

        if(napt_ct_addr[napt.entry_id])
        {
            HNAT_ERR_PRINTK("fault: napt HW:%x can not be overwrited!\n",
                            napt.entry_id);

        }
        else
        {
            napt_ct_addr[napt.entry_id] = ct_addr;
            *hw_index = napt.entry_id;
            // Added from 1.0.7 for default route.
            napt_set_default_route(napt.dst_addr, napt.src_addr);

            return 0;
        }
    }
    else
    {
        HNAT_PRINTK("%s:fail rv:%d entry_id:%x(maybe full)\n",
                    __func__,rv, napt.entry_id);
        nat_hw_pub_ip_del(napt.trans_addr);
    }

    return -1;
}

static a_int32_t
napt_ct_hw_del (napt_entry_t *napt)
{
    if(napt_hw_del(napt)!= 0)
    {
        HNAT_ERR_PRINTK("%s: isis_napt_del fail\n", __func__);
        return -1;
    }
    if(nat_hw_pub_ip_del(napt->trans_addr) != 0)
    {
        HNAT_ERR_PRINTK("%s: public_ip_del fail\n", __func__);
        //return -1;
    }
    return 0;
}

static a_int32_t
napt_ct_del(struct napt_ct *napt_ct, napt_entry_t *napt)
{
    a_uint16_t hw_index = napt->entry_id;

    HNAT_PRINTK("%s: 0x%x ct 0x%x\n", __FUNCTION__, hw_index, napt_ct_addr[hw_index]);

    if(napt_ct_hw_del(napt) != 0)
    {
        return -1;
    }

    NAPT_CT_AGING_ENABLE(napt_ct_addr[hw_index]);
    napt_ct_addr[hw_index] = 0;

    if(napt_ct)
    {
        napt_ct_buf_in_hw_clear(napt_ct);

        if(napt_ct_buf_deny_get(napt_ct) != NAPT_CT_PERMANENT_DENY)
        {
            napt_ct_buf_ct_info_clear(napt_ct);
        }
    }

    return 0;
}

static a_int32_t
napt_ct_del_by_index (struct napt_ct *napt_ct, a_uint16_t hw_index)
{
    napt_entry_t napt = {0};

    if(napt_hw_get_by_index(&napt, hw_index) != 0)
    {
        return -1;
    }

    return napt_ct_del(napt_ct, &napt);
}

static a_int32_t
napt_ct_in_hw_sanity_check(struct napt_ct *napt_ct, a_uint16_t hw_index)
{
    if(!napt_ct)
    {
        HNAT_ERR_PRINTK("<%s>hw_index:%d error napt_ct can't find\n",
                        __func__, hw_index);
        return -1;
    }

    a_uint16_t ct_hw_index;
    if(napt_ct_buf_in_hw_get(napt_ct, &ct_hw_index) == 0)
    {
        HNAT_ERR_PRINTK("<%s>hw_index:%d in_hw:0 error\n",
                        __func__, hw_index);
        return -1;
    }

    if(hw_index != ct_hw_index)
    {
        HNAT_ERR_PRINTK("<%s>hw_index:%d buf_hw_index:%d\n",
                        __func__, hw_index, ct_hw_index);
        return -1;
    }

    return 0;
}

void
napt_ct_hw_aging(void)
{
#define NAPT_AGEOUT_STATUS 1

    a_uint32_t ct_addr;
    napt_entry_t napt = {0};

    HNAT_PRINTK("[aging_scan start]\n");

    if(napt_hw_first_by_age(&napt, NAPT_AGEOUT_STATUS) != 0)
    {
        return;
    }

    do
    {
        a_uint16_t hw_index = napt.entry_id;
        ct_addr = napt_ct_addr[hw_index];

        struct napt_ct *napt_ct = NULL;

        if(ct_addr)
        {
            napt_ct = napt_ct_buf_ct_find(ct_addr);
            if(napt_ct_in_hw_sanity_check(napt_ct, hw_index) != 0)
            {
                HNAT_ERR_PRINTK("<%s> napt_ct_in_hw_sanity_check fail\n", __func__);
                continue;
            }

            if(napt_ct_pkts_reach_thres(ct_addr, napt_ct, 0))
            {
                printk("<aging>set PERMANENT deny ct:%x\n", ct_addr);
                napt_ct_buf_deny_set(napt_ct, NAPT_CT_PERMANENT_DENY);
            }
        }
        else
        {
            HNAT_ERR_PRINTK("<aging> error: in_hw but ct = NULL hw_index:%x\n", hw_index);
        }

        napt_ct_del(napt_ct, &napt);

    }
    while(napt_hw_next_by_age(&napt, NAPT_AGEOUT_STATUS) != -1);

#if 0
    if(napt_hw_used_count_get() == 0)
    {
        nat_hw_prv_base_update_enable();
    }
#endif 

    HNAT_PRINTK("[aging_scan end]\n");

    return;
}


#define NAPT_INVALID_CT_NEED_HW_CLEAR(hw_index)  \
                                ((napt_ct_valid[hw_index] == 0) && \
                                 (napt_ct_addr[hw_index] != 0))
static a_uint32_t
napt_ct_hw_sync(a_uint8_t napt_ct_valid[])
{
    a_uint16_t hw_index;
    a_uint32_t napt_ct_offload_cnt = 0;

    for(hw_index = 0; hw_index < NAPT_TABLE_SIZE; hw_index++)
    {
        if(NAPT_INVALID_CT_NEED_HW_CLEAR(hw_index))
        {

            a_uint32_t ct_addr = napt_ct_addr[hw_index];
            struct napt_ct *napt_ct = napt_ct_buf_ct_find(ct_addr);

            if(napt_ct_in_hw_sanity_check(napt_ct, hw_index) != 0)
            {
                HNAT_ERR_PRINTK("<%s> napt_ct_in_hw_sanity_check fail\n", __func__);
                continue;
            }

            if(napt_ct_del_by_index(napt_ct, hw_index) == 0)
            {
                napt_ct_buf_deny_clear(napt_ct);
            }
            else
            {
                HNAT_ERR_PRINTK("<napt_ct_hw_sync>hw_index:%d napt_hw_del_by_index fail\n",
                                hw_index);
            }
        }

        if(napt_ct_valid[hw_index])
        {
            napt_ct_offload_cnt++;
        }
    }

    return napt_ct_offload_cnt;
}

static void
napt_ct_frag_hw_yield(struct napt_ct *napt_ct, a_uint16_t hw_index)
{
    napt_entry_t napt = {0};

    /*os and hw are both traffic; hw offload giveup*/
    if(napt_hw_get_by_index(&napt, hw_index) == 0)
    {
        if(napt.status == 0xe)
        {
            a_uint8_t deny = napt_ct_buf_deny_get(napt_ct);
            napt_ct_buf_deny_set(napt_ct, (++deny));

            if(deny >= NAPT_CT_PERMANENT_DENY)
            {
                /*os service only*/
                HNAT_ERR_PRINTK("<napt_ct_frag_hw_yield> hw service deny\n");
                napt_ct_del(napt_ct, &napt);
            }

            //printk("<napt_ct_frag_hw_yield> deny:%d\n", deny);
        }
    }
}

#define NAPT_CT_IS_REUSED_BY_OS(in_hw, ct_addr)   ((in_hw) && \
                                    NAPT_CT_AGING_IS_ENABLE(ct_addr))
static a_int32_t
napt_ct_check_add_one(a_uint32_t ct_addr, a_uint8_t *napt_ct_valid)
{
    struct napt_ct *napt_ct = NULL;
    a_uint16_t hw_index;
    a_uint8_t in_hw;
    struct nf_conn *ct = (struct nf_conn *)ct_addr;

    if((napt_ct = napt_ct_buf_ct_find(ct_addr)) == NULL)
    {
        if((napt_ct = napt_ct_buf_ct_add(ct_addr)) == NULL)
        {
            HNAT_ERR_PRINTK("<napt_ct_scan> error hash full\n");
            return -1;
        }
    }

    if(napt_ct_buf_deny_get(napt_ct) >= NAPT_CT_PERMANENT_DENY)
    {
        printk("<napt_ct_scan> ct:%x is PERMANENT deny\n",
               ct_addr);
        return -1;

    }
    else
    {
        if (napt_ct_pkts_reach_thres(ct_addr, napt_ct, 1))
        {
            if(napt_ct_buf_in_hw_get(napt_ct, &hw_index))
            {
                //printk("<napt_ct_scan> ct:%x* is exist\n", ct_addr);
                napt_ct_frag_hw_yield(napt_ct, hw_index);

            }
            else
            {
                if(napt_ct_hw_add(ct_addr, &hw_index) == 0)
                {
                    NAPT_CT_AGING_DISABLE(ct_addr);
                    napt_ct_buf_in_hw_set(napt_ct, hw_index);
#if NAT_TODO
                    ct->in_hnat = 1; /* contrack in HNAT now. */
#endif
                }
            }
        }

        in_hw = napt_ct_buf_in_hw_get(napt_ct, &hw_index);
        if(in_hw)
        {
            if(!NAPT_CT_IS_REUSED_BY_OS(in_hw, ct_addr))
            {
                napt_ct_valid[hw_index] = 1;
            }
        }
    }

    return 0;
}

static void
napt_ct_pkts_thres_calc_init(void)
{
    packets_bdir_total = 0;
    packets_bdir_thres = NAPT_CT_PACKET_THRES_BASE;

}

a_uint64_t
uint64_div_uint32(a_uint64_t div, a_uint32_t base)
{
    register a_uint32_t i;
    a_uint64_t result;

    union
    {
        a_uint64_t n64[2];
        struct
        {
            a_uint32_t l0;// 0
            a_uint32_t h0;// 1
            a_uint32_t l1;// 2
            a_uint32_t h1;// 3
        } n32;
    } n;

    if(base == 0)
    {
        return  0;
    }

    if(div < base)
    {
        return 0;
    }

    n.n64[0] = div;
    n.n64[1] = 0;
    result = 0;
    i = 0;

    //if div is 32bits, set start from 32
    if(n.n32.h0 == 0)
    {
        n.n32.h0 = n.n32.l0;
        n.n32.l0 = 0;
        i = 32;
    }

    //left shift until highest bit
    for(; i<64; ++i)
    {
        if((n.n32.h0 & 0x80000000) == 0x80000000)
        {
            break;
        }
        else
        {
            n.n64[0] = n.n64[0] << 1;
        }
    }

    for (; i<64; ++i)
    {
        n.n64[1] = (n.n64[1] << 1) + (n.n64[0] >> 63);
        n.n64[0] = (n.n64[0] << 1);
        result = result << 1 ;

        if(n.n64[1] >= base)
        {
            n.n64[1] = n.n64[1]- base;
            ++result;
        }
    }

    return result;
}

static void
napt_ct_pkts_thres_calc(a_uint32_t cnt, a_uint32_t napt_ct_offload_cnt)
{
    a_uint64_t packets_bdir_avg = 0;
    a_uint64_t packets_bdir_thres_temp = 0;

    /*ct_avg_pkts* (1+ (ct_offload_cnt/ct_hw_max) )*/
    packets_bdir_avg = uint64_div_uint32(packets_bdir_total, cnt);
    packets_bdir_thres_temp = packets_bdir_avg +
                              uint64_div_uint32((packets_bdir_avg *(a_uint64_t)napt_ct_offload_cnt),
                                      NAPT_TABLE_SIZE);

    if(packets_bdir_thres_temp > NAPT_CT_PACKET_THRES_BASE)
    {
        packets_bdir_thres = packets_bdir_thres_temp;
    }

    //HNAT_ERR_PRINTK("###<%s> total:%lld cnt:%d avg:%lld  threshold:%lld###\n", __func__,
    //    packets_bdir_total, cnt, packets_bdir_avg, packets_bdir_thres);
    HNAT_ERR_PRINTK("calc pkts avg:%lld offload_cnt:%d threshold:%lld\n",
                    packets_bdir_avg, napt_ct_offload_cnt, packets_bdir_thres);
}

#define NAPT_CT_SHOULD_CARE(ct) ((ct) && \
                                  NAPT_CT_TYPE_IS_NAT(ct) && \
                                  NAPT_CT_STATUS_IS_ESTAB(ct) &&\
                                  nat_hw_prv_base_is_match( \
                                            NAPT_CT_PRIV_IP_GET(ct)))
static a_int32_t
napt_ct_check_add(void)
{
    a_uint32_t ct_addr = 0;
    a_uint32_t ct_buf_valid_cnt = 0;
    a_uint32_t hash = 0, iterate = 0;
    a_uint8_t napt_ct_valid[NAPT_TABLE_SIZE] = {0};

    napt_ct_pkts_thres_calc_init();

    NAPT_CT_LIST_LOCK();

    while((ct_addr = NAPT_CT_LIST_ITERATE(&hash, &iterate)))
    {
        if (NAPT_CT_SHOULD_CARE(ct_addr))
        {
            if(napt_ct_check_add_one(ct_addr, napt_ct_valid) != -1)
            {
                ct_buf_valid_cnt++;
            }
        }
    }

    NAPT_CT_LIST_UNLOCK();

    a_uint32_t napt_ct_offload_cnt = napt_ct_hw_sync(napt_ct_valid);

    napt_ct_pkts_thres_calc(ct_buf_valid_cnt, napt_ct_offload_cnt);

    return ct_buf_valid_cnt;
}

static a_int32_t
napt_ct_add(a_uint32_t ct_addr, a_uint8_t *napt_ct_valid)
{
    struct napt_ct *napt_ct;

    if((napt_ct = napt_ct_buf_ct_add(ct_addr)) == NULL)
    {
        HNAT_ERR_PRINTK("<napt_ct_buffer_update> error hash full\n");
        return -1;
    }

    return 0;
}

static a_int32_t
napt_ct_buffer_ct_status_update(void)
{
    a_uint32_t ct_addr = 0;
    a_uint32_t hash = 0;
    a_uint32_t iterate = 0;

    NAPT_CT_LIST_LOCK();

    while((ct_addr = NAPT_CT_LIST_ITERATE(&hash, &iterate)))
    {
        if (NAPT_CT_SHOULD_CARE(ct_addr))
        {
            napt_ct_add(ct_addr, NULL);
        }
    }

    NAPT_CT_LIST_UNLOCK();

    return 0;
}

static void
napt_ct_buffer_hw_status_update(void)
{
    a_uint16_t hw_index;

    for(hw_index = 0; hw_index < NAPT_TABLE_SIZE; hw_index++)
    {
        a_uint32_t ct_addr = napt_ct_addr[hw_index];
        if(ct_addr)
        {
            struct napt_ct *napt_ct = napt_ct_buf_ct_find(ct_addr);
            if(napt_ct)
            {
                napt_ct_buf_in_hw_set(napt_ct, hw_index);

            }
            else
            {
                if(napt_ct_del_by_index(napt_ct, hw_index) != 0)
                {
                    HNAT_ERR_PRINTK("<%s>hw_index:%d napt_ct_del_by_index fail\n",
                                    __func__, hw_index);
                }
            }
        }
    }

    return;
}

static void
napt_ct_buffer_refresh(void)
{
    HNAT_PRINTK("napt_ct_buffer_refresh\n");

    napt_ct_buf_flush();

    napt_ct_buffer_ct_status_update();
    napt_ct_buffer_hw_status_update();
}

static void
napt_ct_buffer_refresh_check(a_uint32_t ct_buf_valid_cnt)
{
#define NAPT_CT_BUF_REFRESH_THRES             1000
    HNAT_ERR_PRINTK("ct_buffer_hash_cnt:%d cnt:%d max:%d\n",
                    napt_ct_cnt_get(), ct_buf_valid_cnt/2, NAPT_CT_BUF_REFRESH_THRES);

    if((napt_ct_cnt_get() - ct_buf_valid_cnt/2) > NAPT_CT_BUF_REFRESH_THRES)
    {
        napt_ct_buffer_refresh();
    }
}

static void
napt_ct_hw_exit(void)
{
    a_uint8_t napt_ct_valid[NAPT_TABLE_SIZE];

    /*set all ct invalid to cleanup*/
    memset(napt_ct_valid, 0, sizeof(napt_ct_valid));

    napt_ct_hw_sync(napt_ct_valid);
}

void
napt_ct_scan(void)
{
    a_uint32_t ct_buf_valid_cnt = 0;

    ct_buf_valid_cnt = napt_ct_check_add();

    napt_ct_buffer_refresh_check(ct_buf_valid_cnt);
}


static a_int32_t
napt_ct_init(void)
{
    napt_hw_mode_init();

    if(napt_ct_buf_init() != 0)
    {
        HNAT_PRINTK("*****napt_ct_buf_init fail*******\n");
        return -1;
    }

    return 0;
}

static a_int32_t
napt_ct_exit(void)
{
    napt_hw_mode_cleanup();

    napt_ct_hw_exit();
    napt_ct_buf_exit();

    return 0;
}

static a_int32_t
napt_ct_scan_thread(void *param)
{
#define NAPT_CT_POLLING_SEC         5
#define NAPT_CT_AGING_SEC           20
#define ARP_CHECK_AGING_SEC       40

    a_uint32_t times = (NAPT_CT_AGING_SEC/NAPT_CT_POLLING_SEC);
    a_uint32_t arp_check_time = (ARP_CHECK_AGING_SEC/NAPT_CT_POLLING_SEC);
    // a_bool_t l3_enable;

    if(napt_ct_init() != 0)
    {
        HNAT_PRINTK("*****napt_ct_init fail*******\n");
        return 0;
    }

    while(1)
    {
		if(!nat_sockopts_init) {
			nat_ipt_sockopts_replace();
		}
        napt_ct_scan();

        if((--times) == 0)
        {
            napt_ct_hw_aging();
            times = (NAPT_CT_AGING_SEC/NAPT_CT_POLLING_SEC);
        }

        if((--arp_check_time) == 0)
        {
            host_check_aging();
            arp_check_time = (ARP_CHECK_AGING_SEC/NAPT_CT_POLLING_SEC);
        }

#ifdef ISISC /* only for S17c */
        napt_set_ipv6_default_route();
#endif
        
        if (NAPT_CT_TASK_SHOULD_STOP())
            break;

        NAPT_CT_TASK_SLEEP(NAPT_CT_POLLING_SEC);
    }

    napt_ct_exit();

    return 0;
}

void
napt_helper_init(void)
{
    const char napt_thread_name[] = "napt_ct_scan";

    NAPT_CT_TASK_START(napt_ct_scan_thread, napt_thread_name);
}


void
napt_helper_exit(void)
{
    NAPT_CT_TASK_STOP();
}

