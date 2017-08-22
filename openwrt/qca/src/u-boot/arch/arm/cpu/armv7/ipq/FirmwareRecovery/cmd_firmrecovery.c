/*!
 *\file		cmd_firmrecovery.c
 *\brief	add an uboot cmd firmrecovery
 *
 *\author	GuoHongwei
 *\version	v1.0
 *\date		12Dec14
 *
 *\history	\arg 1.0, GuoHongwei, 12Dec14, create the file.
 */
/***************************************************************************/
/*                    CONFIGURATIONS                    */
/***************************************************************************/

/***************************************************************************/
/*                    INCLUDE FILES                     */
/***************************************************************************/
#include <common.h>
#include <command.h>

#include <asm/arch-ipq806x/iomap.h>
#include <asm/arch-ipq806x/gpio.h>
#include <asm/io.h>

#include "recovery.h"
#include "recovery_config.h"
/***************************************************************************/
/*                    DEFINES                           */
/***************************************************************************/

/***************************************************************************/
/*                    TYPES                             */
/***************************************************************************/

/***************************************************************************/
/*                    EXTERN_PROTOTYPES                 */
/***************************************************************************/
#ifdef CONFIG_IPQ_SWITCH_PORT_DISABLE
extern void athrs17_all_port_enable(void);
#endif
/***************************************************************************/
/*                    LOCAL_PROTOTYPES                  */
/***************************************************************************/

/***************************************************************************/
/*                    VARIABLES                         */
/***************************************************************************/

/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/
/*
 *\fn           msleep
 *\brief        sleep for some ms
 *
 *\param[in]    ms   the ms to sleep
 *\param[out]   N/A
 *
 *\return       N/A
 */
static void msleep(int ms)
{
	udelay(ms * 1000);
}
/*
 *\fn           get_gpio
 *\brief        get the value of given gpio number
 *
 *\param[in]    gpio   the gpio to check
 *\param[out]   N/A
 *
 *\return       the gpio value
 */
static unsigned long get_gpio(unsigned int gpio)
{
	unsigned int addr;
	unsigned int value;
	addr = GPIO_IN_OUT_ADDR(gpio);
	value = readl(addr);
	return value;
}
/*
 *\fn           set_led_on
 *\brief        turn on the led
 *
 *\param[in]    gpio   the led number to turn on
 *\param[out]   N/A
 *
 *\return       N/A
 */
static void set_led_on(unsigned int gpio)
{
	unsigned int addr;
	if(gpio == -1)
		return;
	gpio_tlmm_config(gpio, 0, 1, 3, 0, 1);
}
/*
 *\fn           set_led_off
 *\brief        turn off the led
 *
 *\param[in]    gpio   the led number to turn off
 *\param[out]   N/A
 *
 *\return       N/A
 */
static void set_led_off(unsigned int gpio)
{
	unsigned int addr;
	if(gpio == -1)
		return;
	gpio_tlmm_config(gpio, 0, 0, 3, 0, 1);
	addr = GPIO_IN_OUT_ADDR(gpio);
	writel(LED_OFF, addr);
}
/***************************************************************************/
/*                    PUBLIC_FUNCTIONS                  */
/***************************************************************************/
/*
 *\fn           do_firmrecovery
 *\brief        recovery from the firmeware
 *
 *\param[in]    the parameters must contained to register the uboot cmd
 *\param[out]   N/A
 *
 *\return       0:success,twinkle led if failed
 */
static int do_firmrecovery(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	int i, flag_on=1;
	int ret = 0;

	unsigned int gpio_reset = REC_GPIO_RESET;

	unsigned int gpio_lan = REC_GPIO_LAN;
	unsigned int gpio_usb_1 = REC_GPIO_USB_1;
	unsigned int gpio_usb_3 = REC_GPIO_USB_3;
	unsigned int gpio_wps = REC_GPIO_WPS;
	unsigned int gpio_status = REC_GPIO_STATUS;
	//unsigned int gpio_wan_orange = 26;
	//unsigned int gpio_wan_blue = 33;
	unsigned int gpio_wlan_2g = -1;
	unsigned int gpio_wlan_5g = -1;
	unsigned int gpio_wlan_60g = -1;

	unsigned int value = 0;

	unsigned int start_time, wait_time;

	char cmd_set_ip[100];
	//char cmd_download_image[1024];

    if (machine_is_tplink_c2600()) {
        gpio_reset = REC_GPIO_RESET;
        gpio_lan = REC_GPIO_LAN;
        gpio_usb_1 = REC_GPIO_USB_1;
        gpio_usb_3 = REC_GPIO_USB_3;
        gpio_wps = REC_GPIO_WPS;
        gpio_status = REC_GPIO_STATUS;
    } else if (machine_is_tplink_ad7200()) {
        gpio_reset = 7;/*RESET*/
        gpio_lan = 2;/*LAN*/
        gpio_usb_1 = 16;/*USB_1*/
        gpio_usb_3 = 8;/*USB_3*/
        gpio_wps = 55;/*WPS*/
        gpio_status = 66;/*STATUS*/
        gpio_wlan_2g = 17;/*WLAN_2G*/
        gpio_wlan_5g = 18;/*WLAN_5G*/
        gpio_wlan_60g = 56;/*WLAN_60G*/
    }

	value = get_gpio(gpio_reset);
	if(value == RESET_PUSH_DOWN)
	{
        msleep(2000);
        value = get_gpio(gpio_reset);
		if (value != RESET_PUSH_DOWN)
		{
			REC_DEBUG("Now doing bootipq");
			run_command("bootipq", 0);
			return 0;
		}
		
		REC_DEBUG("Now doing recovery");
		
#ifdef CONFIG_IPQ_SWITCH_PORT_DISABLE
		athrs17_all_port_enable();
#endif

		//run_command("ledtest 0", 0);

		wait_time = MAX_WAITTIME * 1000;
		start_time = get_timer(0);
		//wps led on
		set_led_on(gpio_wps);

		sprintf(cmd_set_ip, "set ipaddr %s && set serverip %s", IP_ADDR, SERVER_IP);
		run_command(cmd_set_ip, 0);
		//try to connect server
		REC_DEBUG("trying to connect %s ...", SERVER_IP);
		ret = TFTP_timeout(RECOVERY_ADDR, RECOVERY_IMAGE, 5000);
		//connect to server failed
		if(ret == 0)
		{
			i = 0;
			while(1)
			{
				if(i % 2 == 0)
					set_led_off(gpio_wps);
				else
					set_led_on(gpio_wps);
				i++;
				ret = TFTP_timeout(RECOVERY_ADDR, RECOVERY_IMAGE, 1000);
				if(ret == 1)
					break;
				if(get_timer(start_time) > wait_time)
				{
					REC_DEBUG("connect to %s failed, now restart", SERVER_IP);
					set_led_off(gpio_wps);
					run_command("bootipq", 0);
					return 0;
				}
			}
			set_led_on(gpio_wps);
		}
		//download recovery image by TFTP
		//sprintf(cmd_download_image, "tftpboot %s %s", TFTP_DOWNLOAD_ADDR, RECOVERY_IMAGE);
		//run_command(cmd_download_image, 0);
		REC_DEBUG("image downloaded");
		//revovery
		ret = recovery(RECOVERY_ADDR);
		//recovery failed
		if (ret != 0)
		{
			REC_DEBUG("recovery failed");
			start_time = get_timer(0);
			while(1)
			{
				set_led_off(gpio_wps);
				msleep(200);
				set_led_on(gpio_wps);
				msleep(200);
				if(get_timer(start_time) > 3000)
				{
					REC_DEBUG("now restart");
					run_command("reset", 0);
					return 0;
				}
			}
		}
		//recovery success
		set_led_on(gpio_lan);
		set_led_on(gpio_usb_1);
		set_led_on(gpio_usb_3);
		//set_led_on(gpio_wan_orange);
		//set_led_on(gpio_wan_blue);
		set_led_on(gpio_status);
		set_led_on(gpio_wlan_2g);
		set_led_on(gpio_wlan_5g);
		set_led_on(gpio_wlan_60g);
		//let the client notice the led
		msleep(2000);
		run_command("reset", 0);
	}
	else
	{
		REC_DEBUG("Now doing bootipq");
		run_command("bootipq", 0);
	}

	return 0;
}

static int do_led_test(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
    int i = 0;
    int count = 1;
    int interval = 200;

    if (argc > 1) {
        count = argv[1][0] - '0';
        if (count < 0 || count > 9)
            count = 1;
        if (count==0)
            count=-1;
    }
    gpio_tlmm_config(16,0,0,1,0,0);

    while(count--) {
        turn_off_leds();
        ipq_pcie_led_out_one(LED_OFF,0);
        ipq_pcie_led_out_one(LED_OFF,1);
        set_led_on(REC_GPIO_WAN_ORANGE);        
        set_led_on(REC_GPIO_LEDGNR);
        
        while (get_gpio(16)) {
            if (!get_gpio(49)) {
                ipq_pcie_led_out_one(LED_ON,0);
                ipq_pcie_led_out_one(LED_OFF,1);
                msleep(interval);
                ipq_pcie_led_out_one(LED_OFF,0);
                ipq_pcie_led_out_one(LED_ON,1);
                msleep(interval);
                ipq_pcie_led_out_one(LED_OFF,1);
            } else if (!get_gpio(64)) {
                set_led_on(REC_GPIO_STATUS);
                msleep(interval);
                set_led_off(REC_GPIO_STATUS);
            } else if (!get_gpio(65)) {
                set_led_on(REC_GPIO_WPS);
                msleep(interval);
                set_led_off(REC_GPIO_WPS);
            }
            msleep(interval);
        }

        while(!get_gpio(16)) {
            set_led_on(REC_GPIO_LEDGNR);
            msleep(interval);
            set_led_off(REC_GPIO_LEDGNR);
            msleep(interval);
        }

        set_led_on(REC_GPIO_USB_1);msleep(interval);
        set_led_on(REC_GPIO_USB_3);msleep(interval);
        set_led_on(REC_GPIO_WPS);msleep(interval);
        set_led_on(REC_GPIO_LAN);msleep(interval);
        set_led_off(REC_GPIO_WAN_WHITE);msleep(interval);
        ipq_pcie_led_out_one(LED_ON,0);msleep(interval);
        ipq_pcie_led_out_one(LED_ON,1);msleep(interval);
        set_led_on(REC_GPIO_STATUS);msleep(interval);
        set_led_on(REC_GPIO_LEDGNR);msleep(interval);

        turn_off_leds();
        ipq_pcie_led_out_one(LED_OFF,0);
        ipq_pcie_led_out_one(LED_OFF,1);

        set_led_off(REC_GPIO_WAN_ORANGE);
        msleep(500);
        turn_on_leds();
        set_led_off(REC_GPIO_WAN_ORANGE);
        msleep(1000);
    }

    return 0;
}

U_BOOT_CMD(
		   firmrecovery,	1,	0,	do_firmrecovery,
		   "firmware recovery\n",
		   "<firmware recovery\n>"
		   );
U_BOOT_CMD(
		   ledtest,	2,	0,	do_led_test,
		   "ledtest\n",
		   "<ledtest\n>"
		   );
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/
