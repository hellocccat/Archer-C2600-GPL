#ifndef FLASHIO_H
#define FLASHIO_H
/*!
 *\file		flashIO.h
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
extern int flash_probe(void);
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
extern int flash_write(unsigned int addr, unsigned int len, unsigned int buf_addr);
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
extern int flash_read(unsigned int addr, unsigned int len, unsigned int buf_addr);
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
extern int flash_erase(unsigned int addr, unsigned int len);
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/

#endif