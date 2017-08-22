/*
 * Copyright (c) 2012, The Linux Foundation. All rights reserved.
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

#include "sw.h"
#include "ssdk_init.h"
#include "fal_init.h"
#include "fal_misc.h"
#include "fal_mib.h"
#include "fal_port_ctrl.h"
#include "fal_portvlan.h"
#include "fal_fdb.h"
#include "fal_stp.h"
#include "fal_igmp.h"
#include "fal_qos.h"
#include "hsl.h"
#include "hsl_dev.h"
#include "ssdk_init.h"
#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/types.h>
//#include <asm/mach-types.h>
#include <generated/autoconf.h>
#if defined(CONFIG_OF) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
#include <linux/switch.h>
#else
#include <net/switch.h>
#include <linux/ar8216_platform.h>
#endif
#include <linux/delay.h>
#include <linux/phy.h>
#include <linux/netdevice.h>
#include "ssdk_plat.h"
#include "ref_vlan.h"

int
qca_ar8327_sw_get_port_link(struct switch_dev *dev, int port,
			                        struct switch_port_link *link)
{
	struct qca_phy_priv *priv = qca_phy_priv_get(dev);

	fal_port_speed_t speed;
	fal_port_duplex_t duplex;
	a_bool_t status;
	a_bool_t tx_fc;
	a_bool_t rx_fc;
	a_uint32_t ret;

	mutex_lock(&priv->reg_mutex);
	ret = fal_port_link_status_get(0, port, &status);
	if (ret){
		mutex_unlock(&priv->reg_mutex);
		return -1;
	}

	ret = fal_port_speed_get(0, port, &speed);
	if (ret){
		mutex_unlock(&priv->reg_mutex);
		return -1;
	}

	ret = fal_port_duplex_get(0, port, &duplex);
	if (ret){
		mutex_unlock(&priv->reg_mutex);
		return -1;
	}

	ret = fal_port_rxfc_status_get(0, port, &rx_fc);
	if (ret){
		mutex_unlock(&priv->reg_mutex);
		return -1;
	}

	ret = fal_port_txfc_status_get(0, port, &tx_fc);
	if (ret){
		mutex_unlock(&priv->reg_mutex);
		return -1;
	}
	mutex_unlock(&priv->reg_mutex);

	link->link = status;
	if (speed == FAL_SPEED_10){
		link->speed = SWITCH_PORT_SPEED_10;
	} else if (speed == FAL_SPEED_100){
		link->speed = SWITCH_PORT_SPEED_100;
	} else if (speed == FAL_SPEED_1000){
		link->speed = SWITCH_PORT_SPEED_1000;
	} else {
		link->speed = SWITCH_PORT_SPEED_UNKNOWN;
	}

	if (duplex == FAL_HALF_DUPLEX){
		link->duplex = 0; /* HALF */
	} else if (duplex == FAL_FULL_DUPLEX){
		link->duplex = 1; /* FULL */
	}

	link->rx_flow = rx_fc;
	link->tx_flow = tx_fc;

	return 0;
}

