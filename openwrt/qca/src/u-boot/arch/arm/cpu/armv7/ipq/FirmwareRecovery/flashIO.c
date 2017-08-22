/*!
 *\file		flashIO.c
 *\brief	control the flash read and write
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
#include <spi_flash.h>
#include <asm/io.h>

#include "flashIO.h"
#include "recovery.h"
/***************************************************************************/
/*                    DEFINES                           */
/***************************************************************************/
#ifndef CONFIG_SF_DEFAULT_SPEED
# define CONFIG_SF_DEFAULT_SPEED	1000000
#endif
#ifndef CONFIG_SF_DEFAULT_MODE
# define CONFIG_SF_DEFAULT_MODE		SPI_MODE_3
#endif
#ifndef CONFIG_SF_DEFAULT_CS
# define CONFIG_SF_DEFAULT_CS		0
#endif
#ifndef CONFIG_SF_DEFAULT_BUS
# define CONFIG_SF_DEFAULT_BUS		0
#endif
/***************************************************************************/
/*                    TYPES                             */
/***************************************************************************/
/*
 *\struct   client_table
 *\brief    table inode of clients
 */
/***************************************************************************/
/*                    EXTERN_PROTOTYPES                 */
/***************************************************************************/

/***************************************************************************/
/*                    LOCAL_PROTOTYPES                  */
/***************************************************************************/

/***************************************************************************/
/*                    VARIABLES                         */
/***************************************************************************/
struct spi_flash *flash = NULL;
/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/

/***************************************************************************/
/*                    PUBLIC_FUNCTIONS                  */
/***************************************************************************/
/*
 *\fn           flash_probe
 *\brief        init flash device on given SPI bus and chip select
 *
 *\param[in]    N/A
 *\param[out]   N/A
 *
 *\return       0:success,1:failed
 */
int flash_probe(void)
{
	unsigned int bus = CONFIG_SF_DEFAULT_BUS;
	unsigned int cs = CONFIG_SF_DEFAULT_CS;
	unsigned int speed = CONFIG_SF_DEFAULT_SPEED;
	unsigned int mode = CONFIG_SF_DEFAULT_MODE;
	struct spi_flash *new;

	new = spi_flash_probe(bus, cs, speed, mode);
	if (!new) {
		REC_ERROR("Failed to initialize SPI flash at %u:%u\n", bus, cs);
		return 1;
	}

	if (flash)
		spi_flash_free(flash);
	flash = new;

	return 0;
}
/*
 *\fn           flash_write
 *\brief        write buff to given address
 *
 *\param[in]    addr       the flash address to write begin
 *\             len        the buff length to write
 *\             buf_addr   the buff address in memry to write from
 *\param[out]   N/A
 *
 *\return       0:success,1:failed
 */
int flash_write(unsigned int addr, unsigned int len, unsigned int buf_addr)
{
	void *buf;
	int ret;

	buf = map_physmem(buf_addr, len, MAP_WRBACK);
	if (!buf) {
		REC_ERROR("Failed to map physical memory");
		return 1;
	}

	ret = spi_flash_write(flash, addr, len, buf);

	unmap_physmem(buf, len);

	if (ret)
	{
		REC_ERROR("SPI write flash failed:%X,%X\n", addr, len);
		return 1;
	}
	return 0;
}
/*
 *\fn           flash_read
 *\brief        read buff from given address
 *
 *\param[in]    addr       the flash address to read begin
 *\             len        the buff length to read
 *\             buf_addr   the buff address in memry to read to
 *\param[out]   N/A
 *
 *\return       0:success,1:failed
 */
int flash_read(unsigned int addr, unsigned int len, unsigned int buf_addr)
{
	void *buf;
	int ret;

	buf = map_physmem(buf_addr, len, MAP_WRBACK);
	if (!buf) {
		REC_ERROR("Failed to map physical memory");
		return 1;
	}

	ret = spi_flash_read(flash, addr, len, buf);

	unmap_physmem(buf, len);

	if (ret)
	{
		REC_ERROR("SPI read flash failed:%X,%X\n", addr, len);
		return 1;
	}
	return 0;
}
/*
 *\fn           flash_erase
 *\brief        erase flash from given address
 *
 *\param[in]    addr       the flash address to erase begin
 *\             len        the buff length to erase
 *\param[out]   N/A
 *
 *\return       0:success,1:failed
 */
int flash_erase(unsigned int addr, unsigned int len)
{
	int ret;

	ret = spi_flash_erase(flash, addr, len);
	if (ret)
	{
		REC_ERROR("SPI erase flash failed:%X,%X\n", addr, len);
		return 1;
	}
	return 0;
}
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/
