/* Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/* nss_cfi_ipsec.c
 *	NSS IPsec offload glue for Openswan/KLIPS
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/dst.h>

#include <nss_api_if.h>
#include <nss_crypto_if.h>
#include <nss_ipsec.h>
#include <nss_cfi_if.h>
#include "nss_ipsecmgr.h"

#define NSS_CFI_IPSEC_BASE_NAME "ipsec"
#define NSS_CFI_IPSEC_TUN_IFNAME(x) NSS_CFI_IPSEC_BASE_NAME#x

/*
 * This is used by KLIPS for communicate the device along with the
 * packet. We need this to derive the mapping of the incoming flow
 * to the IPsec tunnel
 */
struct nss_cfi_ipsec_skb_cb {
	struct net_device *hlos_dev;
};

/*
 * Per tunnel object created w.r.t the HLOS IPsec stack
 */
struct nss_cfi_ipsec_sa {
	enum nss_ipsecmgr_rule_type type;
	struct net_device *nss_dev;

	union {
		struct nss_ipsecmgr_encap_del encap;
		struct nss_ipsecmgr_decap_del decap;
	} rule_del;
};

/*
 * CFI IPsec netdevice  mapping between HLOS devices and NSS devices
 * Essentially various HLOS IPsec devices will be used as indexes to
 * map into the NSS devices. For example
 * "ipsec0" --> "ipsectun0"
 * "ipsec1" --> "ipsectun1"
 *
 * Where the numeric suffix of "ipsec0", "ipsec1" is used to index into
 * the table
 */
struct nss_cfi_ipsec_tunnel {
	struct net_device *nss_dev;
};

/*
 ************************
 * Globals
 ***********************
 */
/*
 * List of supported tunnels in Openswan/KLIPS
 */
const static uint8_t *max_tun_supp[] = {
	NSS_CFI_IPSEC_TUN_IFNAME(0),	/* ipsec0 */
	NSS_CFI_IPSEC_TUN_IFNAME(1),	/* ipsec1 */
};
#define NSS_CFI_IPSEC_MAX_TUN (sizeof(max_tun_supp) / sizeof(max_tun_supp[0]))

struct nss_cfi_ipsec_tunnel tunnel_map[NSS_CFI_IPSEC_MAX_TUN];	/* per tunnel device table */
struct nss_cfi_ipsec_sa sa_tbl[NSS_CRYPTO_MAX_IDXS];		/* per crypto session table */

/*
 * nss_cfi_ipsec_get_iv_len
 * 	get ipsec algorithm specific iv len
 */
static int32_t nss_cfi_ipsec_get_iv_len(uint32_t algo)
{
	uint32_t result = -1;

	switch (algo) {
		case NSS_CRYPTO_CIPHER_AES:
			result = NSS_CRYPTO_MAX_IVLEN_AES;
			break;

		case NSS_CRYPTO_CIPHER_DES:
			result = NSS_CRYPTO_MAX_IVLEN_DES;
			break;

		case NSS_CRYPTO_CIPHER_NULL:
			result = NSS_CRYPTO_MAX_IVLEN_NULL;
			break;

		default:
			nss_cfi_err("Invalid algorithm\n");
			break;
	}
	return result;
}

/*
 * nss_cfi_ipsec_get_dev()
 * 	get ipsec netdevice from skb. Openswan stack fills up ipsec_dev in skb.
 */
static inline struct net_device * nss_cfi_ipsec_get_dev(struct sk_buff *skb)
{
	struct nss_cfi_ipsec_skb_cb *ipsec_cb;

	ipsec_cb = (struct nss_cfi_ipsec_skb_cb *)skb->cb;

	return ipsec_cb->hlos_dev;
}

/*
 * nss_cfi_ipsec_verify_ifname()
 * 	Verify the IPsec tunnel interface name
 *
 * This will ensure that only supported interface names
 * are used for tunnel creation
 */
static bool nss_cfi_ipsec_verify_ifname(uint8_t *name)
{
	int i;

	for (i = 0; i < NSS_CFI_IPSEC_MAX_TUN; i++) {
		if (strncmp(name, max_tun_supp[i], strlen(max_tun_supp[i])) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * nss_cfi_ipsec_get_index()
 * 	given a interface name retrived the numeric suffix
 */
static int16_t nss_cfi_ipsec_get_index(uint8_t *name)
{
	uint16_t idx;

	if (nss_cfi_ipsec_verify_ifname(name) == false) {
		return -1;
	}

	name += strlen(NSS_CFI_IPSEC_BASE_NAME);

	for (idx = 0; (*name >= '0') && (*name <= '9'); name++) {
		idx = (*name - '0') + (idx * 10);
	}

	if (idx >= NSS_CFI_IPSEC_MAX_TUN) {
		return -1;
	}

	return idx;
}

/*
 * nss_cfi_ipsec_get_next_hdr()
 * 	get next hdr after IPv4 header.
 */
static inline void * nss_cfi_ipsec_get_next_hdr(struct iphdr *ip)
{
	return ((uint8_t *)ip + sizeof(struct iphdr));
}

/*
 * nss_cfi_ipsec_free_session()
 * 	Free perticular session on NSS.
 */
static int32_t nss_cfi_ipsec_free_session(uint32_t crypto_sid)
{
	struct nss_cfi_ipsec_sa *sa;
	bool status;

	sa = &sa_tbl[crypto_sid];

	status = nss_ipsecmgr_sa_del(sa->nss_dev, (union nss_ipsecmgr_rule *)&sa->rule_del, sa->type);
	if (status == false) {
		return -1;
	}

	return 0;
}

/*
 * nss_cfi_ipsec_trap_encap()
 * 	Trap IPsec pkts for sending encap fast path rules.
 */
static int32_t nss_cfi_ipsec_trap_encap(struct sk_buff *skb, struct nss_cfi_crypto_info* crypto)
{
	union nss_ipsecmgr_rule rule = {{0}};
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	struct ip_esp_hdr *esp = NULL;
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;
	struct net_device *hlos_dev;
	struct net_device *nss_dev;
	uint32_t index = 0;
	struct nss_ipsecmgr_encap_del *encap_del;
	uint32_t ivsize = 0;

	hlos_dev = nss_cfi_ipsec_get_dev(skb);
	if (hlos_dev == NULL) {
		nss_cfi_err("ipsec dev is NULL\n");
		return -1;
	}

	ivsize = nss_cfi_ipsec_get_iv_len(crypto->cipher_algo);
	if (ivsize < 0) {
		nss_cfi_err("Invalid IV\n");
		return -1;
	}

	outer_ip = (struct iphdr *)skb->data;
	esp = (struct ip_esp_hdr *)(skb->data + sizeof(struct iphdr));
	/* XXX: this should use the IV len fed by CFI */
	inner_ip = (struct iphdr *)(skb->data + sizeof(struct iphdr) + sizeof(struct ip_esp_hdr) + ivsize);

	if ((outer_ip->version != IPVERSION) || (outer_ip->ihl != 5)) {
		nss_cfi_dbg("Outer non-IPv4 packet {0x%x, 0x%x}\n", outer_ip->version, outer_ip->ihl);
		return 0;
	}

	if ((inner_ip->version != IPVERSION) || (inner_ip->ihl != 5)) {
		nss_cfi_dbg("Inner non-IPv4 packet {0x%x, 0x%x}\n", inner_ip->version, inner_ip->ihl);
		return -1;
	}

	skb->skb_iif = hlos_dev->ifindex;

	rule.encap_add.inner_ipv4_src = ntohl(inner_ip->saddr);
	rule.encap_add.inner_ipv4_dst = ntohl(inner_ip->daddr);

	rule.encap_add.outer_ipv4_src = ntohl(outer_ip->saddr);
	rule.encap_add.outer_ipv4_dst = ntohl(outer_ip->daddr);
	rule.encap_add.esp_spi = ntohl(esp->spi);

	switch(inner_ip->protocol)
	{
		case IPPROTO_TCP:
			tcp = nss_cfi_ipsec_get_next_hdr(inner_ip);
			rule.encap_add.inner_src_port = ntohs(tcp->source);
			rule.encap_add.inner_dst_port = ntohs(tcp->dest);
			break;
		case IPPROTO_UDP:
			udp = nss_cfi_ipsec_get_next_hdr(inner_ip);
			rule.encap_add.inner_src_port = ntohs(udp->source);
			rule.encap_add.inner_dst_port = ntohs(udp->dest);
			break;
		default:
			nss_cfi_err("inner IPv4 header mismatch:protocol = %d\n", inner_ip->protocol);
			return -1;
	}

	/* XXX:All this needs to be fed by CFI */
	rule.encap_add.cipher_algo = crypto->cipher_algo;
	rule.encap_add.esp_icv_len = crypto->hash_len;
	rule.encap_add.auth_algo = crypto->auth_algo;
	rule.encap_add.crypto_index = crypto->sid;
	rule.encap_add.nat_t_req = 0;

	rule.encap_add.inner_ipv4_proto = inner_ip->protocol;
	rule.encap_add.outer_ipv4_ttl = outer_ip->ttl;

	index = nss_cfi_ipsec_get_index(hlos_dev->name);
	if (index < 0) {
		return -1;
	}

	nss_dev = tunnel_map[index].nss_dev;

	if(nss_ipsecmgr_sa_add(nss_dev, &rule, NSS_IPSECMGR_RULE_TYPE_ENCAP) == false) {
		nss_cfi_err("Error in Pushing the Encap Rule \n");
		return -1;
	}

	/*
	 * Need to save the selector for deletion as it will for issued for
	 * session delete
	 */

	sa_tbl[crypto->sid].type = NSS_IPSECMGR_RULE_TYPE_ENCAP;
	sa_tbl[crypto->sid].nss_dev = nss_dev;

	encap_del = &sa_tbl[crypto->sid].rule_del.encap;

	encap_del->inner_ipv4_src = rule.encap_add.inner_ipv4_src;
	encap_del->inner_ipv4_dst = rule.encap_add.inner_ipv4_dst;
	encap_del->inner_src_port = rule.encap_add.inner_src_port;
	encap_del->inner_dst_port = rule.encap_add.inner_dst_port;
	encap_del->inner_ipv4_proto = rule.encap_add.inner_ipv4_proto;

	nss_cfi_dbg("encap pushed rule successfully\n");

	return 0;
}

/*
 * nss_cfi_ipsec_trap_decap()
 * 	Trap IPsec pkts for sending decap fast path rules.
 */
static int32_t nss_cfi_ipsec_trap_decap(struct sk_buff *skb, struct nss_cfi_crypto_info* crypto)
{
	union nss_ipsecmgr_rule rule = {{0}};
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	struct ip_esp_hdr *esp = NULL;
	struct net_device *hlos_dev;
	struct net_device *nss_dev;
	struct nss_ipsecmgr_decap_del *decap_del;
	uint8_t index = 0;
	uint32_t ivsize = 0;

	hlos_dev = nss_cfi_ipsec_get_dev(skb);
	if (hlos_dev == NULL) {
		nss_cfi_err("hlos dev is NULL\n");
		return -1;
	}

	ivsize = nss_cfi_ipsec_get_iv_len(crypto->cipher_algo);
	if (ivsize < 0) {
		nss_cfi_err("Invalid IV\n");
		return -1;
	}

	skb->skb_iif = hlos_dev->ifindex;

	outer_ip = (struct iphdr *)skb_network_header(skb);
	esp = (struct ip_esp_hdr *)skb->data;
	/* XXX: this should use the IV len fed by CFI */
	inner_ip = (struct iphdr *)(skb->data + sizeof(struct ip_esp_hdr) + ivsize);

	rule.decap_add.outer_ipv4_src = ntohl(outer_ip->saddr);
	rule.decap_add.outer_ipv4_dst = ntohl(outer_ip->daddr);

	rule.decap_add.esp_spi = ntohl(esp->spi);

	/* XXX:All this needs to be fed by CFI */
	rule.decap_add.cipher_algo = crypto->cipher_algo;
	rule.decap_add.auth_algo = crypto->auth_algo;
	rule.decap_add.esp_icv_len = crypto->hash_len;
	rule.decap_add.crypto_index = crypto->sid;

	/* XXX:This needs to come from openswan */
	rule.decap_add.window_size = 0;

	index = nss_cfi_ipsec_get_index(hlos_dev->name);
	if (index < 0) {
		return -1;
	}

	nss_dev = tunnel_map[index].nss_dev;

	if(nss_ipsecmgr_sa_add(nss_dev, &rule, NSS_IPSECMGR_RULE_TYPE_DECAP) == false) {
		nss_cfi_err("Error in Pushing the Decap Rule\n");
		return -1;
	}

	/*
	 * Need to save the selector for deletion as it will for issued for
	 * session delete
	 */
	sa_tbl[crypto->sid].type = NSS_IPSECMGR_RULE_TYPE_DECAP;
	sa_tbl[crypto->sid].nss_dev = nss_dev;

	decap_del = &sa_tbl[crypto->sid].rule_del.decap;

	decap_del->outer_ipv4_src = rule.decap_add.outer_ipv4_src;
	decap_del->outer_ipv4_dst = rule.decap_add.outer_ipv4_dst;
	decap_del->esp_spi = rule.decap_add.esp_spi;

	nss_cfi_dbg("decap pushed rule successfully\n");

	return 0;
}

/*
 * nss_ipsec_data_cb()
 * 	ipsec exception routine for handling exceptions from NSS IPsec package
 *
 * exception function called by NSS HLOS driver when it receives
 * a packet for exception with the interface number for decap
 */
static void nss_cfi_ipsec_data_cb(void *cb_ctx, struct sk_buff *skb)
{
	struct net_device *dev = cb_ctx;
	struct iphdr *ip;

	nss_cfi_dbg("exception data ");

	/*
	 * need to hold the lock prior to accessing the dev
	 */
	if(!dev) {
		dev_kfree_skb_any(skb);
		return;
	}

	dev_hold(dev);

	ip = (struct iphdr *)skb->data;


	if ((ip->version != IPVERSION ) || (ip->ihl != 5)) {
		nss_cfi_dbg("unkown ipv4 header\n");
		dev_kfree_skb_any(skb);
		return;
	}

	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = cpu_to_be16(ETH_P_IP);
	skb->dev = dev;
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);

	dev_put(dev);

	nss_cfi_dbg("delivered\n");
}

/*
 * nss_ipsec_ev_cb()
 * 	Receive events from NSS IPsec package
 *
 * Event callback called by IPsec manager
 */
static void nss_cfi_ipsec_ev_cb(void *ctx, struct nss_ipsecmgr_event *ev)
{
	switch (ev->type) {

	default:
		nss_cfi_dbg("unknown IPsec manager event\n");
		break;
	}
}

/*
 * nss_cfi_ipsec_dev_event()
 * 	notifier function for IPsec device events.
 */
static int nss_cfi_ipsec_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *hlos_dev = (struct net_device *)ptr;
	struct net_device *nss_dev;
	int16_t index = 0;

	switch (event) {
	case NETDEV_UP:

		index = nss_cfi_ipsec_get_index(hlos_dev->name);
		if (index < 0) {
			return NOTIFY_DONE;
		}

		nss_cfi_info("IPsec interface being registered: %s\n", hlos_dev->name);

		nss_dev = nss_ipsecmgr_tunnel_add(hlos_dev, nss_cfi_ipsec_data_cb, nss_cfi_ipsec_ev_cb);
		if (nss_dev == NULL) {
			nss_cfi_err("NSS IPsec tunnel dev allocation failed for %s\n", hlos_dev->name);
			return NOTIFY_BAD;
		}


		tunnel_map[index].nss_dev = nss_dev;

		break;

        case NETDEV_UNREGISTER:

		index = nss_cfi_ipsec_get_index(hlos_dev->name);
		if (index < 0) {
			return NOTIFY_DONE;
		}

		nss_dev = tunnel_map[index].nss_dev;
		if (nss_dev == NULL) {
			return NOTIFY_DONE;
		}

		nss_cfi_info("IPsec interface being unregistered: %s\n", hlos_dev->name);

		nss_ipsecmgr_tunnel_del(nss_dev);

		tunnel_map[index].nss_dev = NULL;

		break;

	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block nss_cfi_ipsec_notifier = {
	.notifier_call = nss_cfi_ipsec_dev_event,
};

/*
 * nss_ipsec_init_module()
 * 	Initialize IPsec rule tables and register various callbacks
 */
int __init nss_cfi_ipsec_init_module(void)
{
	nss_cfi_info("NSS IPsec (platform - IPQ806x , Build - %s:%s) loaded\n", __DATE__, __TIME__);

	register_netdevice_notifier(&nss_cfi_ipsec_notifier);

	nss_cfi_ocf_register_ipsec(nss_cfi_ipsec_trap_encap, nss_cfi_ipsec_trap_decap, nss_cfi_ipsec_free_session);

	return 0;
}

/*
 * nss_ipsec_exit_module()
 */
void __exit nss_cfi_ipsec_exit_module(void)
{
	nss_cfi_ocf_unregister_ipsec();

	unregister_netdevice_notifier(&nss_cfi_ipsec_notifier);

	nss_cfi_info("module unloaded\n");
}


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Qualcomm Atheros");
MODULE_DESCRIPTION("NSS IPsec offload glue");

module_init(nss_cfi_ipsec_init_module);
module_exit(nss_cfi_ipsec_exit_module);

