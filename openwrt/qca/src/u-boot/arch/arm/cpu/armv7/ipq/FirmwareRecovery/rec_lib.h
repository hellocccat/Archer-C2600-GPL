#ifndef REC_LIB_H
#define REC_LIB_H
/*!
 *\file		rec_lib.h
 *\brief	the needed function to recovery
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
extern int rec_str_split(const char *buf, int len, const char *split, char *argv[], int maxargc);
/*
 *\fn           hextoint
 *\brief        change the hex buff to unsigned int
 *
 *\param[in]    hex       the buff of hex
 *\param[out]   N/A
 *
 *\return       unsigned int value changed from the hex buff
 */
extern unsigned int hextoint(const char *hex);
/*
 *\fn           TFTP_timeout
 *\brief        check if TFTP server is active in given time
 *
 *\param[in]    load_address   the address to save the file
 *\             filename       the file to get
 *\             mtimeout       the time value to check,ms
 *\param[out]   N/A
 *
 *\return       1:active;0:not active
 */
extern int TFTP_timeout(unsigned long load_address, const char* filename, unsigned int mtimeout);
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/

#endif