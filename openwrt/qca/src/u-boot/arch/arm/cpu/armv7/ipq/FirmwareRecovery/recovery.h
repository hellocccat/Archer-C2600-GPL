#ifndef RECOVERY_H
#define RECOVERY_H
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
#define REC_ERROR(fmt,arg...) printf("FirmwareRecovery: "fmt",file :%s,line :%d\n", ##arg, __FILE__, __LINE__)
#define REC_DEBUG(fmt,arg...) printf("FirmwareRecovery: "fmt"\n", ##arg)

#define NM_FLASH_SIZE		0x2000000

#define IMAGE_SIZE_LEN		(0x04)
#define IMAGE_SIZE_MD5		(0x10)
#define IMAGE_SIZE_PRODUCT	(0x1000)
#define IMAGE_SIZE_BASE (IMAGE_SIZE_LEN + IMAGE_SIZE_MD5 + IMAGE_SIZE_PRODUCT)

#define IMAGE_SIZE_MAX  (IMAGE_SIZE_BASE + 0x800 + NM_FLASH_SIZE)
#define IMAGE_SIZE_MIN  (IMAGE_SIZE_BASE + 0x800)

#define IMAGE_INDEX_SIZE	2000
#define IMAGE_UPDATE_INDEX_SIZE	2048

#define PARTITION_MAX_NUM	32
#define PARTIYION_NAME_LEN	20

#define SUPPORT_LIST_MAX_NUM	32
#define PRODUCT_INFO_MAX_NUM	32
/***************************************************************************/
/*                    TYPES                             */
/***************************************************************************/
typedef struct _rec_partition 
{
	char name[PARTIYION_NAME_LEN];
	unsigned int base;
	unsigned int size;
	unsigned int datastart;
	unsigned int datalen;
	unsigned int need_head;
}rec_partition;
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
 *\fn           recovery
 *\brief        recovery the DUT from firmware image
 *
 *\param[in]    addr   the address of buff containing the image
 *\param[out]   N/A
 *
 *\return       0:success,1:failed
 */
extern int recovery(unsigned int addr);
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/

#endif