/*
 *	Linux ethernet bridge
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 *	Distribute under GPLv2.
 *
 */

#ifdef CONFIG_BRIDGE_VLAN

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include "br_private.h"
#include "br_vlan.h"



void br_show_vlan_map()
{
	printk("\n----ifmap----\n");
/*	printk("%8s %8s %8s %8s %8s\n", "index", "ifindex", "pvid", "tag", "vlanmap");
	for(index = 1; index < BR_VLAN_IF_NUM; index ++)
	{
		if(if_list[index].ifindex > 0)
		{
			printk("%8d %8d %8d %8s"
					, index
					, if_list[index].ifindex
					, if_list[index].pvid
					, if_list[index].tag?"tag":"untag");
			for(index2 = 0 ; index2 < BR_VLAN_VLAN_PER_IF; index2++)
			{
				printk(" %4d",if_list[index].vlan_map[index2]);
			}
			printk("\n");
		}
	}*/
	printk("-------------\n");
}

bool br_vlan_forward_hook(const struct net_bridge_port *p, const struct sk_buff *skb)
{
	struct net_bridge_port *psrc;

	psrc = br_port_get_rcu(skb->dev);

	if(!psrc)
	{
		return 1;
	}

	if((!psrc->vlan_id) || (!p->vlan_id) )
	{
		BR_VLAN_PRINT("accept %d->%d", psrc->vlan_id , p->vlan_id);
		return 1;
	}

	if(psrc->vlan_id == p->vlan_id)
	{
		BR_VLAN_PRINT("accept %d->%d", psrc->vlan_id , p->vlan_id);
		return 1;
	}
	else
	{
		BR_VLAN_PRINT("deny %d->%d", psrc->vlan_id , p->vlan_id);
		return 0;
	}
}

int br_set_if_vlan(struct net_bridge *br, struct net_device *dev, int vlan_id)
{
	struct net_bridge_port *p;

	p = br_port_get_rtnl(dev);
	if (!p || p->br != br)
		return -EINVAL;

	p->vlan_id = vlan_id;

	return 0;
}

#endif
