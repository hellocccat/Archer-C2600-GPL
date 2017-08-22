/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
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


/**
 * @defgroup dess_init DESS_INIT
 * @{
 */
#include "sw.h"
#include "hsl.h"
#include "hsl_dev.h"
#include "hsl_port_prop.h"
#include "dess_mib.h"
#include "dess_port_ctrl.h"
#include "dess_portvlan.h"
#include "dess_vlan.h"
#include "dess_fdb.h"
#include "dess_qos.h"
#include "dess_mirror.h"
#include "dess_stp.h"
#include "dess_rate.h"
#include "dess_misc.h"
#include "dess_leaky.h"
#include "dess_igmp.h"
#include "dess_acl.h"
#include "dess_led.h"
#include "dess_cosmap.h"
#include "dess_ip.h"
#include "dess_nat.h"
#if defined(IN_NAT_HELPER)
#include "dess_nat_helper.h"
#endif
#include "dess_sec.h"
#include "dess_trunk.h"
#include "dess_interface_ctrl.h"
#include "dess_reg_access.h"
#include "dess_reg.h"
#include "dess_init.h"


static ssdk_init_cfg * dess_cfg[SW_MAX_NR_DEV] = { 0 };
a_uint32_t dess_nat_global_status = 0;

#if !(defined(KERNEL_MODULE) && defined(USER_MODE))
/* For isis there are five internal PHY devices and seven MAC devices.
   PORT0 always connect to external DMA device.
   MAC1..MAC4 connect to internal PHY0..PHY3.
*/
enum dess_port_cfg {
	PORT_WRAPPER_PSGMII = 0,
	PORT_WRAPPER_PSGMII_RGMII,
	PORT_WRAPPER_PSGMII_RMII0,
	PORT_WRAPPER_PSGMII_RMII1,
	PORT_WRAPPER_PSGMII_RMII0_RMII1,
	PORT_WRAPPER_SGMII,
	PORT_WRAPPER_SGMII_RGMII,
	PORT_WRAPPER_SGMII_RMII0,
	PORT_WRAPPER_SGMII_RMII1,
	PORT_WRAPPER_SGMII_RMII0_RMII1,
	PORT_WRAPPER_MAX
};

a_uint32_t dess_pbmp[PORT_WRAPPER_MAX] = {
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*PORT_WRAPPER_PSGMII*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*PORT_WRAPPER_PSGMII_RGMII*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*PORT_WRAPPER_PSGMII_RMII0*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*PORT_WRAPPER_PSGMII_RMII1*/
	((1<<1) | (1<<2) | (1<<3) | (1<<4) | (1<<5)), /*PORT_WRAPPER_PSGMII_RMII0_RMII1*/
	(1<<1),                                       /*PORT_WRAPPER_SGMII*/
	((1<<1) | (1<<5)),                            /*PORT_WRAPPER_SGMII_RGMII*/
	((1<<1) | (1<<5)),                            /*PORT_WRAPPER_SGMII_RMII0*/
	((1<<1) | (1<<4)),                            /*PORT_WRAPPER_SGMII_RMII1*/
	((1<<1) | (1<<4) | (1<<5))                    /*PORT_WRAPPER_SGMII_RMII0_RMII1*/
	};


enum dess_port_cfg dess_get_port_config()
{
	/*get the efused id*/

	return PORT_WRAPPER_PSGMII;
}

a_bool_t dess_mac_port_valid_check(fal_port_t port_id)
{
	a_uint32_t bitmap = 0;
	enum dess_port_cfg cfg;

	cfg = dess_get_port_config();
	bitmap = dess_pbmp[cfg];

	return SW_IS_PBMP_MEMBER(bitmap, port_id);

}

static sw_error_t
dess_portproperty_init(a_uint32_t dev_id, hsl_init_mode mode)
{
    hsl_port_prop_t p_type;
    hsl_dev_t *pdev = NULL;
    fal_port_t port_id;
	enum dess_port_cfg cfg;
	a_uint32_t bitmap = 0;



    pdev = hsl_dev_ptr_get(dev_id);
    if (pdev == NULL)
        return SW_NOT_INITIALIZED;

	cfg = dess_get_port_config();
	bitmap = dess_pbmp[cfg];

    /* for port property set, SSDK should not generate some limitations */
    for (port_id = 0; port_id < pdev->nr_ports; port_id++)
    {
        hsl_port_prop_portmap_set(dev_id, port_id);

        for (p_type = HSL_PP_PHY; p_type < HSL_PP_BUTT; p_type++)
        {
            if (HSL_NO_CPU == mode)
            {
                SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
                continue;
            }

            switch (p_type)
            {
                case HSL_PP_PHY:
                    /* Only port0 without PHY device */
                    if (port_id != pdev->cpu_port_nr)
                    {
						if(SW_IS_PBMP_MEMBER(bitmap, port_id))
                        	SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
                    }
                    break;

                case HSL_PP_INCL_CPU:
                    /* include cpu port but exclude wan port in some cases */
                    /* but which port is wan port, we are no meaning */
					if (port_id == pdev->cpu_port_nr)
						SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
					if(SW_IS_PBMP_MEMBER(bitmap, port_id))
                    	SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
                    break;

                case HSL_PP_EXCL_CPU:
                    /* exclude cpu port and wan port in some cases */
                    /* which port is wan port, we are no meaning but port0 is
                       always CPU port */
                    if (port_id != pdev->cpu_port_nr)
                    {
						if(SW_IS_PBMP_MEMBER(bitmap, port_id))
                        	SW_RTN_ON_ERROR(hsl_port_prop_set(dev_id, port_id, p_type));
                    }
                    break;

                default:
                    break;
            }
        }

        if (HSL_NO_CPU == mode)
        {
            SW_RTN_ON_ERROR(hsl_port_prop_set_phyid
                            (dev_id, port_id, port_id + 1));
        }
        else
        {
            if (port_id != pdev->cpu_port_nr)
            {
                SW_RTN_ON_ERROR(hsl_port_prop_set_phyid
                                (dev_id, port_id, port_id - 1));
            }
        }
    }

    return SW_OK;
}
/*linchen remove it??*/
#if 0
static sw_error_t
dess_hw_init(a_uint32_t dev_id, ssdk_init_cfg *cfg)
{
    return SW_OK;
}
#endif
#endif

static sw_error_t
dess_dev_init(a_uint32_t dev_id, hsl_init_mode cpu_mode)
{
    a_uint32_t entry;
    sw_error_t rv;
    hsl_dev_t *pdev = NULL;

    pdev = hsl_dev_ptr_get(dev_id);
    if (pdev == NULL)
        return SW_NOT_INITIALIZED;

    HSL_REG_FIELD_GET(rv, dev_id, MASK_CTL, 0, DEVICE_ID,
                      (a_uint8_t *) (&entry), sizeof (a_uint32_t));
    SW_RTN_ON_ERROR(rv);
/*linchen: force as dess*/
#if 0
    if (S17C_DEVICE_ID == entry)
    {
        pdev->nr_ports = 7;
        pdev->nr_phy = 5;
        pdev->cpu_port_nr = 0;
        pdev->nr_vlans = 4096;
        pdev->hw_vlan_query = A_TRUE;
        pdev->nr_queue = 6;
        pdev->cpu_mode = cpu_mode;
    }
    else
#endif
    if (DESS_DEVICE_ID == entry)
    {
        pdev->nr_ports = 6;
        pdev->nr_phy = 5;
        pdev->cpu_port_nr = 0;
        pdev->nr_vlans = 4096;
        pdev->hw_vlan_query = A_TRUE;
        pdev->nr_queue = 6;
        pdev->cpu_mode = cpu_mode;
    }

    return SW_OK;
}

sw_error_t
dess_cleanup(a_uint32_t dev_id)
{
    if (dess_cfg[dev_id])
    {
#if defined(IN_NAT_HELPER)
        sw_error_t rv;
        if(dess_nat_global_status)
            DESS_NAT_HELPER_CLEANUP(rv, dev_id);
#endif

        aos_mem_free(dess_cfg[dev_id]);
        dess_cfg[dev_id] = NULL;
    }

    return SW_OK;
}

/**
 * @brief Init hsl layer.
 * @details Comments:
 *   This operation will init hsl layer and hsl layer
 * @param[in] dev_id device id
 * @param[in] cfg configuration for initialization
 * @return SW_OK or error code
 */
sw_error_t
dess_init(a_uint32_t dev_id, ssdk_init_cfg *cfg)
{
    HSL_DEV_ID_CHECK(dev_id);

    if (NULL == dess_cfg[dev_id])
    {
        dess_cfg[dev_id] = aos_mem_alloc(sizeof (ssdk_init_cfg));
    }

    if (NULL == dess_cfg[dev_id])
    {
        return SW_OUT_OF_MEM;
    }

    aos_mem_copy(dess_cfg[dev_id], cfg, sizeof (ssdk_init_cfg));

    SW_RTN_ON_ERROR(dess_reg_access_init(dev_id, cfg->reg_mode));

    SW_RTN_ON_ERROR(dess_dev_init(dev_id, cfg->cpu_mode));

#if !(defined(KERNEL_MODULE) && defined(USER_MODE))
    {
        sw_error_t rv;

        SW_RTN_ON_ERROR(hsl_port_prop_init());/*linchen port property????*/
        SW_RTN_ON_ERROR(hsl_port_prop_init_by_dev(dev_id));
        SW_RTN_ON_ERROR(dess_portproperty_init(dev_id, cfg->cpu_mode));

        DESS_MIB_INIT(rv, dev_id);
        DESS_PORT_CTRL_INIT(rv, dev_id);
        DESS_PORTVLAN_INIT(rv, dev_id);
        DESS_VLAN_INIT(rv, dev_id);
        DESS_FDB_INIT(rv, dev_id);
        DESS_QOS_INIT(rv, dev_id);
        DESS_STP_INIT(rv, dev_id);
        DESS_MIRR_INIT(rv, dev_id);
        DESS_RATE_INIT(rv, dev_id);
        DESS_MISC_INIT(rv, dev_id);
        DESS_LEAKY_INIT(rv, dev_id);
        DESS_IGMP_INIT(rv, dev_id);
        DESS_ACL_INIT(rv, dev_id);
        DESS_LED_INIT(rv, dev_id);
        DESS_COSMAP_INIT(rv, dev_id);
        DESS_IP_INIT(rv, dev_id);
        DESS_NAT_INIT(rv, dev_id);
        DESS_TRUNK_INIT(rv, dev_id);
        DESS_SEC_INIT(rv, dev_id);
        DESS_INTERFACE_CTRL_INIT(rv, dev_id);

        {
            hsl_api_t *p_api;

            SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));
            p_api->dev_clean   = dess_cleanup;
        }
#if 0
#if defined(IN_NAT_HELPER)
		if(!dess_nat_global_status) {
        	DESS_NAT_HELPER_INIT(rv, dev_id);
			dess_nat_global_status = 1;
		}
#endif
#endif
    }
#endif

    return SW_OK;
}

/**
 * @}
 */

