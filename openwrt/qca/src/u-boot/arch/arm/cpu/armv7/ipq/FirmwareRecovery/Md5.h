#ifndef MD5_H
#define MD5_H
/*!
 *\file		Md5.h
 *\brief	check the Md5 of firmware image
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
#ifdef _LP64
typedef unsigned int UINT4;
typedef int          INT4;
#else
typedef unsigned int UINT4;
typedef long          INT4;
#endif
#define _UINT4_T

#define  MD5_LEN	16
/***************************************************************************/
/*                    TYPES                             */
/***************************************************************************/
/* Data structure for MD5 (Message-Digest) computation */
typedef struct {
	UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
	UINT4 buf[4];                                    /* scratch buffer */
	unsigned char in[64];                              /* input buffer */
	unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;
/***************************************************************************/
/*                    EXTERN_PROTOTYPES                 */
/***************************************************************************/

/***************************************************************************/
/*                    LOCAL_PROTOTYPES                  */
/***************************************************************************/

/***************************************************************************/
/*                    VARIABLES                         */
/***************************************************************************/
extern unsigned char md5ImageKey[16];
/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/

/***************************************************************************/
/*                    PUBLIC_FUNCTIONS                  */
/***************************************************************************/
/*
 *\fn           check_Md5
 *\brief        check if the buff has the right md5
 *\param[in]    md5   the target md5
 *              buf   the buff to check
 *              len   the length of buff
 *\param[out]   N/A
 *
 *\return       1:the same md5,0:failed
 */
extern int check_Md5(const unsigned char*md5, const unsigned char *buf, unsigned int len);
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/

#endif