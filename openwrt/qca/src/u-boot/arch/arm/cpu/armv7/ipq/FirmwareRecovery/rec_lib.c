/*!
 *\file        rec_lib.c
 *\brief    the needed function to recovery
 *
 *\author    GuoHongwei
 *\version    v1.0
 *\date        12Dec14
 *
 *\history    \arg 1.0, GuoHongwei, 12Dec14, create the file.
 */
/***************************************************************************/
/*                    CONFIGURATIONS                    */
/***************************************************************************/

/***************************************************************************/
/*                    INCLUDE FILES                     */
/***************************************************************************/
#include <common.h>
#include <malloc.h>
#include <linux/ctype.h>
#include <watchdog.h>
#include <net.h>

#include "rec_lib.h"
#include "recovery.h"
#include "tftp.h"
#include "recovery_config.h"

DECLARE_GLOBAL_DATA_PTR;
/***************************************************************************/
/*                    DEFINES                           */
/***************************************************************************/

/***************************************************************************/
/*                    TYPES                             */
/***************************************************************************/

/***************************************************************************/
/*                    EXTERN_PROTOTYPES                 */
/***************************************************************************/

/***************************************************************************/
/*                    LOCAL_PROTOTYPES                  */
/***************************************************************************/

/***************************************************************************/
/*                    VARIABLES                         */
/***************************************************************************/

/* Network loop restarted */
static int    NetRestarted;
/* At least one device configured */
static int    NetDevExists;
static int NetTryCount;

/* Current timeout handler */
static thand_f *timeHandler;
/* Time base value */
static ulong    timeStart;
/* Current timeout value */
static ulong    timeDelta;
/* THE transmit packet */
//uchar *NetTxPacket;

//uchar PktBuf[(PKTBUFSRX+1) * PKTSIZE_ALIGN + PKTALIGN];

/* Network loop state */
extern enum net_loop_state net_state;
/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/
static void NetInitLoop(void)
{
    static int env_changed_id;
    int env_id = get_env_id();

    /* update only when the environment has changed */
    if (env_changed_id != env_id) {
        NetOurIP = getenv_IPaddr("ipaddr");
        NetOurGatewayIP = getenv_IPaddr("gatewayip");
        NetOurSubnetMask = getenv_IPaddr("netmask");
        NetServerIP = getenv_IPaddr("serverip");
        NetOurNativeVLAN = getenv_VLAN("nvlan");
        NetOurVLAN = getenv_VLAN("vlan");
#if defined(CONFIG_CMD_DNS)
        NetOurDNSIP = getenv_IPaddr("dnsip");
#endif
        env_changed_id = env_id;
    }
    memcpy(NetOurEther, eth_get_dev()->enetaddr, 6);

    return;
}
static void net_clear_handlers(void)
{
    net_set_udp_handler(NULL);
    net_set_arp_handler(NULL);
    NetSetTimeout(0, NULL);
}
static void net_cleanup_loop(void)
{
    net_clear_handlers();
}
/*
static void net_init(void)
{
    static int first_call = 1;

    if (first_call) {
        / *
         *    Setup packet buffers, aligned correctly.
         * /
        int i;

        NetTxPacket = &PktBuf[0] + (PKTALIGN - 1);
        NetTxPacket -= (ulong)NetTxPacket % PKTALIGN;
        for (i = 0; i < PKTBUFSRX; i++)
            NetRxPackets[i] = NetTxPacket + (i + 1) * PKTSIZE_ALIGN;

        ArpInit();
        net_clear_handlers();

        / * Only need to setup buffer pointers once. * /
        first_call = 0;
    }

    NetInitLoop();
}*/

/*
 *\fn           rec_str_contain
 *\brief        test if buff contains the char
 *
 *\param[in]    buf   the buff to test
 *\             ch    the char to check
 *\param[out]   N/A
 *
 *\return       1:contained,0:not contained
 */
static int rec_str_contain(const char *buf, const char ch)
{
    int i = 0;

    if(buf == NULL)
        return 0;

    while (buf[i] != '\0')
    {
        if(buf[i] == ch)
            return 1;
        i++;
    }
    return 0;
}
/***************************************************************************/
/*                    PUBLIC_FUNCTIONS                  */
/***************************************************************************/
/*
 *\fn           rec_str_split
 *\brief        split the buff by the given chars
 *
 *\param[in]    buf       the buff to split
 *\             len       the buff length
 *\             split     the chars to split buff
 *\             argv      the buff array to contains the splited words
 *\             maxargc   the max number to split to
 *\param[out]   N/A
 *
 *\return       the number of words splited to,return 0 if more than the maxargc
 */
int rec_str_split(const char *buf, int len, const char *split, char *argv[], int maxargc)
{
    int index = 0;
    int i = 0;
    int str_begin = 0;
    int length;
    int ret = 0;

    while (i < len)
    {
        if (buf[i] == '\0' || rec_str_contain(split, buf[i]) == 1)
        {
            if (i > str_begin)
            {
                if (index == maxargc)
                {
                    REC_ERROR("too many partitions");
                    ret = 0;
                    goto err_out;
                }
                length = i - str_begin;
                argv[index] = malloc(length + 1);
                memcpy(argv[index], buf + str_begin, length);
                argv[index][length] = '\0';
                index++;
            }
            if (buf[i] == '\0')
            {
                ret = index;
                goto done;
            }
            str_begin = i + 1;
        }
        i++;
    }
err_out:
    for (i = 0;i < index;i++)
        free(argv[i]);
done:
    return ret;
}
/*
 *\fn           hextoint
 *\brief        change the hex buff to unsigned int
 *
 *\param[in]    hex       the buff of hex
 *\param[out]   N/A
 *
 *\return       unsigned int value changed from the hex buff
 */
unsigned int hextoint(const char *hex)
{
    int i = 0;
    unsigned int val = 0;
    int n;

    while (hex[i] != 'x')
        i++;
    i++;
    while (hex[i] != '\0')
    {
        if(hex[i] >= 'a')
            n = hex[i] - 'a' + 10;
        else if(hex[i] >= 'A')
            n = hex[i] - 'A' + 10;
        else
            n = hex[i] - '0';
        val = (val << 4) + n;
        i++;
    }
    return val;
}

/*
 *\fn           TFTP_timeout
 *\brief        load file by TFTP in given time
 *
 *\param[in]    load_address   the address to save the file
 *\             filename       the file to get
 *\             mtimeout       the time value to wait,ms
 *\param[out]   N/A
 *
 *\return       1:active;0:not active
 */
int TFTP_timeout(unsigned long load_address, const char* filename, unsigned int mtimeout)
{
    bd_t *bd = gd->bd;
    int ret = 0;
    unsigned long start_time;
    int ret_rx1 =0,ret_rx2 = 0;

    start_time = get_timer(0);

    bootstage_mark_name(BOOTSTAGE_KERNELREAD_START, "tftp_start");

    //get parameter
    load_addr = load_address;
    memset(BootFile, 0, sizeof(BootFile));
    memcpy(BootFile, filename, strlen(filename));
    //REC_DEBUG("Trying loading %s ...", BootFile);
    bootstage_mark(BOOTSTAGE_ID_NET_START);

    //init net state
    NetRestarted = 0;
    NetDevExists = 0;
    NetTryCount = 1;
    bootstage_mark_name(BOOTSTAGE_ID_ETH_START, "eth_start");
    net_init();
    eth_halt();
    eth_set_current();
    if (eth_init(bd) < 0)
    {
        //REC_DEBUG("init net error");
        eth_halt();
        ret = 0;
        goto done;
    }

restart:
    //check if timeout
    if (get_timer(start_time) > mtimeout)
    {
        REC_DEBUG("try connect timeout");
        ret = 0;
        goto done;
    }
    //check TFTP state
    net_set_state(NETLOOP_CONTINUE);
    NetInitLoop();
    if (NetServerIP == 0)
    {
        REC_DEBUG("*** ERROR: `serverip' not set");
        eth_halt();
        ret = 0;
        goto done;
    }

    //try connect
    NetDevExists = 1;
    NetBootFileXferSize = 0;
    TftpStart(TFTPGET);
    for (;;)
    {

    //check if timeout
        if (ret_rx2 < 4096)  // fail 2 times
        {
                    if (get_timer(start_time) > mtimeout)
            {
            REC_DEBUG("TFTP:try connect timeout");
            ret = 0;
            goto done;
            }
                }

        WATCHDOG_RESET();
#ifdef CONFIG_SHOW_ACTIVITY
        show_activity(1);
#endif
        ret_rx1 = eth_rx();
                if(ret_rx2 < 4096)
                    {
                        ret_rx2 += ret_rx1;
                        //REC_DEBUG("RX:%d", ret_rx2);
                    }

        //ctrl-c was pressed
        if (ctrlc())
        {
            REC_DEBUG("\nAbort");
            /* cancel any ARP that may not have completed */
            //NetArpWaitPacketIP = 0;
            net_cleanup_loop();
            eth_halt();
            ret = 0;
            goto done;
        }
        ArpTimeoutCheck();
        if (timeHandler && ((get_timer(0) - timeStart) > timeDelta))
        {
            thand_f *x;

            REC_DEBUG("--- NetLoop timeout\n");
            x = timeHandler;
            timeHandler = (thand_f *)0;
            (*x)();
        }
        switch (net_state)
        {
        case NETLOOP_RESTART:
            NetRestarted = 1;
            goto restart;

        case NETLOOP_SUCCESS:
            net_cleanup_loop();
            if (NetBootFileXferSize > 0)
            {
                char buf[20];
                printf("Bytes transferred = %ld (%lx hex)\n",
                    NetBootFileXferSize,
                    NetBootFileXferSize);
                sprintf(buf, "%lX", NetBootFileXferSize);
                setenv("filesize", buf);

                sprintf(buf, "%lX", (unsigned long)load_addr);
                setenv("fileaddr", buf);
            }
            eth_halt();
            ret = 1;
            goto done;

        case NETLOOP_FAIL:
            REC_DEBUG("--- NetLoop Fail!\n");
            net_cleanup_loop();
            ret = 0;
            goto done;

        case NETLOOP_CONTINUE:
            continue;
        }
    }
done:
    bootstage_mark_name(BOOTSTAGE_KERNELREAD_STOP, "tftp_done");
    return ret;
}

/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/
