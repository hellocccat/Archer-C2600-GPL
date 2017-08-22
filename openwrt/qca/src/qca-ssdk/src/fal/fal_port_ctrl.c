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


/**
 * @defgroup fal_port_ctrl FAL_PORT_CONTROL
 * @{
 */
#include "sw.h"
#include "fal_port_ctrl.h"
#include "hsl_api.h"


static sw_error_t
_fal_port_duplex_set(a_uint32_t dev_id, fal_port_t port_id,
                     fal_port_duplex_t duplex)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_duplex_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_duplex_set(dev_id, port_id, duplex);
    return rv;
}


static sw_error_t
_fal_port_duplex_get(a_uint32_t dev_id, fal_port_t port_id,
                     fal_port_duplex_t * pduplex)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_duplex_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_duplex_get(dev_id, port_id, pduplex);
    return rv;
}


static sw_error_t
_fal_port_speed_set(a_uint32_t dev_id, fal_port_t port_id,
                    fal_port_speed_t speed)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_speed_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_speed_set(dev_id, port_id, speed);
    return rv;
}


static sw_error_t
_fal_port_speed_get(a_uint32_t dev_id, fal_port_t port_id,
                    fal_port_speed_t * pspeed)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_speed_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_speed_get(dev_id, port_id, pspeed);
    return rv;
}


static sw_error_t
_fal_port_autoneg_status_get(a_uint32_t dev_id, fal_port_t port_id,
                             a_bool_t * status)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_autoneg_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_autoneg_status_get(dev_id, port_id, status);
    return rv;
}


static sw_error_t
_fal_port_autoneg_enable(a_uint32_t dev_id, fal_port_t port_id)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_autoneg_enable)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_autoneg_enable(dev_id, port_id);
    return rv;
}


static sw_error_t
_fal_port_autoneg_restart(a_uint32_t dev_id, fal_port_t port_id)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_autoneg_restart)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_autoneg_restart(dev_id, port_id);
    return rv;
}


static sw_error_t
_fal_port_autoneg_adv_set(a_uint32_t dev_id, fal_port_t port_id,
                          a_uint32_t autoadv)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_autoneg_adv_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_autoneg_adv_set(dev_id, port_id, autoadv);
    return rv;
}

static sw_error_t
_fal_port_autoneg_adv_get(a_uint32_t dev_id, fal_port_t port_id,
                          a_uint32_t * autoadv)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_autoneg_adv_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_autoneg_adv_get(dev_id, port_id, autoadv);
    return rv;
}


static sw_error_t
_fal_port_hdr_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_hdr_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_hdr_status_set(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_hdr_status_get(a_uint32_t dev_id, fal_port_t port_id,
                         a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_hdr_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_hdr_status_get(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_flowctrl_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_flowctrl_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_flowctrl_set(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_flowctrl_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_flowctrl_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_flowctrl_get(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_flowctrl_forcemode_set(a_uint32_t dev_id, fal_port_t port_id,
                                 a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_flowctrl_forcemode_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_flowctrl_forcemode_set(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_flowctrl_forcemode_get(a_uint32_t dev_id, fal_port_t port_id,
                                 a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_flowctrl_forcemode_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_flowctrl_forcemode_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_powersave_set(a_uint32_t dev_id, fal_port_t port_id,
                        a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_powersave_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_powersave_set(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_powersave_get(a_uint32_t dev_id, fal_port_t port_id,
                        a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_powersave_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_powersave_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_hibernate_set(a_uint32_t dev_id, fal_port_t port_id,
                        a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_hibernate_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_hibernate_set(dev_id, port_id, enable);
    return rv;
}


static sw_error_t
_fal_port_hibernate_get(a_uint32_t dev_id, fal_port_t port_id,
                        a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_hibernate_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_hibernate_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_cdt(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t mdi_pair,
              a_uint32_t *cable_status, a_uint32_t *cable_len)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_cdt)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_cdt(dev_id, port_id, mdi_pair, cable_status, cable_len);
    return rv;
}

static sw_error_t
_fal_port_rxhdr_mode_set(a_uint32_t dev_id, fal_port_t port_id,
                         fal_port_header_mode_t mode)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxhdr_mode_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxhdr_mode_set(dev_id, port_id, mode);
    return rv;
}

static sw_error_t
_fal_port_rxhdr_mode_get(a_uint32_t dev_id, fal_port_t port_id,
                         fal_port_header_mode_t * mode)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxhdr_mode_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxhdr_mode_get(dev_id, port_id, mode);
    return rv;
}

static sw_error_t
_fal_port_txhdr_mode_set(a_uint32_t dev_id, fal_port_t port_id,
                         fal_port_header_mode_t mode)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txhdr_mode_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txhdr_mode_set(dev_id, port_id, mode);
    return rv;
}

static sw_error_t
_fal_port_txhdr_mode_get(a_uint32_t dev_id, fal_port_t port_id,
                         fal_port_header_mode_t * mode)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txhdr_mode_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txhdr_mode_get(dev_id, port_id, mode);
    return rv;
}

static sw_error_t
_fal_header_type_set(a_uint32_t dev_id, a_bool_t enable, a_uint32_t type)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->header_type_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->header_type_set(dev_id, enable, type);
    return rv;
}

static sw_error_t
_fal_header_type_get(a_uint32_t dev_id, a_bool_t * enable, a_uint32_t * type)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->header_type_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->header_type_get(dev_id, enable, type);
    return rv;
}

static sw_error_t
_fal_port_txmac_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txmac_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txmac_status_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_txmac_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txmac_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txmac_status_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_rxmac_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxmac_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxmac_status_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_rxmac_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxmac_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxmac_status_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_txfc_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txfc_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txfc_status_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_txfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_txfc_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_txfc_status_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_rxfc_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxfc_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxfc_status_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_rxfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_rxfc_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_rxfc_status_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_bp_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_bp_status_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_bp_status_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_bp_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_bp_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_bp_status_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_link_forcemode_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_link_forcemode_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_link_forcemode_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_link_forcemode_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_link_forcemode_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_link_forcemode_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_link_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * status)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_link_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_link_status_get(dev_id, port_id, status);
    return rv;
}

static sw_error_t
_fal_ports_link_status_get(a_uint32_t dev_id, a_uint32_t * status)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->ports_link_status_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->ports_link_status_get(dev_id, status);
    return rv;
}

static sw_error_t
_fal_port_mac_loopback_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_mac_loopback_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_mac_loopback_set(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_mac_loopback_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_mac_loopback_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_mac_loopback_get(dev_id, port_id, enable);
    return rv;
}

static sw_error_t
_fal_port_congestion_drop_set(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t queue_id, a_bool_t enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_congestion_drop_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_congestion_drop_set(dev_id, port_id, queue_id, enable);
    return rv;
}

static sw_error_t
_fal_port_congestion_drop_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t queue_id, a_bool_t * enable)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->port_congestion_drop_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->port_congestion_drop_get(dev_id, port_id, queue_id, enable);
    return rv;
}

static sw_error_t
_fal_ring_flow_ctrl_thres_set(a_uint32_t dev_id, a_uint32_t ring_id, a_uint8_t on_thres, a_uint8_t off_thres)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->ring_flow_ctrl_thres_set)
        return SW_NOT_SUPPORTED;

    rv = p_api->ring_flow_ctrl_thres_set(dev_id, ring_id, on_thres, off_thres);
    return rv;
}

static sw_error_t
_fal_ring_flow_ctrl_thres_get(a_uint32_t dev_id, a_uint32_t ring_id, a_uint8_t *on_thres, a_uint8_t *off_thres)
{
    sw_error_t rv;
    hsl_api_t *p_api;

    SW_RTN_ON_NULL(p_api = hsl_api_ptr_get(dev_id));

    if (NULL == p_api->ring_flow_ctrl_thres_get)
        return SW_NOT_SUPPORTED;

    rv = p_api->ring_flow_ctrl_thres_get(dev_id, ring_id, on_thres, off_thres);
    return rv;
}




/**
 * @brief Set duplex mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] duplex duplex mode
 * @return SW_OK or error code
 */
sw_error_t
fal_port_duplex_set(a_uint32_t dev_id, fal_port_t port_id,
                    fal_port_duplex_t duplex)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_duplex_set(dev_id, port_id, duplex);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get duplex mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] duplex duplex mode
 * @return SW_OK or error code
 */
sw_error_t
fal_port_duplex_get(a_uint32_t dev_id, fal_port_t port_id,
                    fal_port_duplex_t * pduplex)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_duplex_get(dev_id, port_id, pduplex);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set speed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] speed port speed
 * @return SW_OK or error code
 */
sw_error_t
fal_port_speed_set(a_uint32_t dev_id, fal_port_t port_id,
                   fal_port_speed_t speed)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_speed_set(dev_id, port_id, speed);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get speed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] speed port speed
 * @return SW_OK or error code
 */
sw_error_t
fal_port_speed_get(a_uint32_t dev_id, fal_port_t port_id,
                   fal_port_speed_t * pspeed)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_speed_get(dev_id, port_id, pspeed);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get auto negotiation status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] status A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_autoneg_status_get(a_uint32_t dev_id, fal_port_t port_id,
                            a_bool_t * status)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_autoneg_status_get(dev_id, port_id, status);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Enable auto negotiation status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @return SW_OK or error code
 */
sw_error_t
fal_port_autoneg_enable(a_uint32_t dev_id, fal_port_t port_id)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_autoneg_enable(dev_id, port_id);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Restart auto negotiation procedule on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @return SW_OK or error code
 */
sw_error_t
fal_port_autoneg_restart(a_uint32_t dev_id, fal_port_t port_id)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_autoneg_restart(dev_id, port_id);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set auto negotiation advtisement ability on a particular port.
 *   @details  Comments:
 *   auto negotiation advtisement ability is defined by macro such as
 *   FAL_PHY_ADV_10T_HD, FAL_PHY_ADV_PAUSE...
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] autoadv auto negotiation advtisement ability bit map
 * @return SW_OK or error code
 */
sw_error_t
fal_port_autoneg_adv_set(a_uint32_t dev_id, fal_port_t port_id,
                         a_uint32_t autoadv)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_autoneg_adv_set(dev_id, port_id, autoadv);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get auto negotiation advtisement ability on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] autoadv auto negotiation advtisement ability bit map
 * @return SW_OK or error code
 */
sw_error_t
fal_port_autoneg_adv_get(a_uint32_t dev_id, fal_port_t port_id,
                         a_uint32_t * autoadv)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_autoneg_adv_get(dev_id, port_id, autoadv);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_hdr_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_hdr_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_hdr_status_get(a_uint32_t dev_id, fal_port_t port_id,
                        a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_hdr_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set flow control status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_flowctrl_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_flowctrl_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get flow control status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_flowctrl_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_flowctrl_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set flow control force mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_flowctrl_forcemode_set(a_uint32_t dev_id, fal_port_t port_id,
                                a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_flowctrl_forcemode_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get flow control force mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_flowctrl_forcemode_get(a_uint32_t dev_id, fal_port_t port_id,
                                a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_flowctrl_forcemode_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set powersaving status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_powersave_set(a_uint32_t dev_id, fal_port_t port_id,
                       a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_powersave_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get powersaving status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_powersave_get(a_uint32_t dev_id, fal_port_t port_id,
                       a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_powersave_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set hibernate status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_hibernate_set(a_uint32_t dev_id, fal_port_t port_id,
                       a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_hibernate_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get hibernate status on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_hibernate_get(a_uint32_t dev_id, fal_port_t port_id,
                       a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_hibernate_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief cable diagnostic test.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] mdi_pair mdi pair id
 * @param[out] cable_status cable status
 * @param[out] cable_len cable len
 * @return SW_OK or error code
 */
sw_error_t
fal_port_cdt(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t mdi_pair,
             a_uint32_t *cable_status, a_uint32_t *cable_len)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_cdt(dev_id, port_id, mdi_pair, cable_status, cable_len);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxhdr_mode_set(a_uint32_t dev_id, fal_port_t port_id,
                        fal_port_header_mode_t mode)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_rxhdr_mode_set(dev_id, port_id, mode);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxhdr_mode_get(a_uint32_t dev_id, fal_port_t port_id,
                        fal_port_header_mode_t * mode)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_rxhdr_mode_get(dev_id, port_id, mode);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txhdr_mode_set(a_uint32_t dev_id, fal_port_t port_id,
                        fal_port_header_mode_t mode)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_txhdr_mode_set(dev_id, port_id, mode);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of Atheros header packets parsed on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txhdr_mode_get(a_uint32_t dev_id, fal_port_t port_id,
                        fal_port_header_mode_t * mode)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_txhdr_mode_get(dev_id, port_id, mode);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of Atheros header type value on a particular device.
 * @param[in] dev_id device id
 * @param[in] enable A_TRUE or A_FALSE
 * @param[in] type header type value
 * @return SW_OK or error code
 */
sw_error_t
fal_header_type_set(a_uint32_t dev_id, a_bool_t enable, a_uint32_t type)
{
    sw_error_t rv;
    FAL_API_LOCK;
    rv = _fal_header_type_set(dev_id, enable, type);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of Atheros header type value on a particular device.
 * @param[in] dev_id device id
 * @param[out] enable A_TRUE or A_FALSE
 * @param[out] type header type value
 * @return SW_OK or error code
 */
sw_error_t
fal_header_type_get(a_uint32_t dev_id, a_bool_t * enable, a_uint32_t * type)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_header_type_get(dev_id, enable, type);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of txmac on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txmac_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    FAL_API_LOCK;
    rv = _fal_port_txmac_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of txmac on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txmac_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_txmac_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of rxmac on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxmac_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    FAL_API_LOCK;
    rv = _fal_port_rxmac_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of rxmac on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxmac_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_rxmac_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of tx flow control on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txfc_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;
    FAL_API_LOCK;
    rv = _fal_port_txfc_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get status of tx flow control on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_txfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_txfc_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of rx flow control on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxfc_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_rxfc_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of rx flow control on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_rxfc_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_rxfc_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of back pressure on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_bp_status_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_bp_status_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set status of back pressure on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_bp_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_bp_status_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set link force mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_link_forcemode_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_link_forcemode_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get link force mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_link_forcemode_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_link_forcemode_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get link status on particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] status link status up (A_TRUE) or down (A_FALSE)
 * @return SW_OK or error code
 */
sw_error_t
fal_port_link_status_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * status)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_link_status_get(dev_id, port_id, status);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get link status on all ports.
 * @param[in] dev_id device id
 * @param[out] status link status bitmap and bit 0 for port 0, bit 1 for port 1, ...etc.
 * @return SW_OK or error code
 */
sw_error_t
fal_ports_link_status_get(a_uint32_t dev_id, a_uint32_t * status)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_ports_link_status_get(dev_id, status);
    FAL_API_UNLOCK;
    return rv;
}


/**
 * @brief Set loopback on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_mac_loopback_set(a_uint32_t dev_id, fal_port_t port_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_mac_loopback_set(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get link force mode on a particular port.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_mac_loopback_get(a_uint32_t dev_id, fal_port_t port_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_mac_loopback_get(dev_id, port_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set congestion drop on a particular port queue.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_congestion_drop_set(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t queue_id, a_bool_t enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_congestion_drop_set(dev_id, port_id, queue_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get congestion drop on a particular port queue.
 * @param[in] dev_id device id
 * @param[in] port_id port id
 * @param[in] queue_id queue_id
 * @param[out] enable A_TRUE or A_FALSE
 * @return SW_OK or error code
 */
sw_error_t
fal_port_congestion_drop_get(a_uint32_t dev_id, fal_port_t port_id, a_uint32_t queue_id, a_bool_t * enable)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_port_congestion_drop_get(dev_id, port_id, queue_id, enable);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Set flow control threshold on a DMA ring.
 * @param[in] dev_id device id
 * @param[in] ring_id ring_id
 * @param[in] on_thres on_thres
 * @param[in] off_thres on_thres
 * @return SW_OK or error code
 */
sw_error_t
fal_ring_flow_ctrl_thres_set(a_uint32_t dev_id, a_uint32_t ring_id, a_uint8_t on_thres, a_uint8_t off_thres)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_ring_flow_ctrl_thres_set(dev_id, ring_id, on_thres, off_thres);
    FAL_API_UNLOCK;
    return rv;
}

/**
 * @brief Get flow control threshold on a DMA ring.
 * @param[in] dev_id device id
 * @param[in] ring_id ring_id
 * @param[out] on_thres on_thres
 * @param[out] off_thres on_thres
 * @return SW_OK or error code
 */
sw_error_t
fal_ring_flow_ctrl_thres_get(a_uint32_t dev_id, a_uint32_t ring_id, a_uint8_t *on_thres, a_uint8_t *off_thres)
{
    sw_error_t rv;

    FAL_API_LOCK;
    rv = _fal_ring_flow_ctrl_thres_get(dev_id, ring_id, on_thres, off_thres);
    FAL_API_UNLOCK;
    return rv;
}



/**
 * @}
 */

