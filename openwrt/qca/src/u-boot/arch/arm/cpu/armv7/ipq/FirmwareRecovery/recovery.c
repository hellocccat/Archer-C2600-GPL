/*!
 *\file		recovery.c
 *\brief	recovery the DUT from firmware image
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
#include <malloc.h>

#include "recovery.h"
#include "Md5.h"
#include "flashIO.h"
#include "rec_lib.h"
/***************************************************************************/
/*                    DEFINES                           */
/***************************************************************************/

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
//partition need to recovery
rec_partition rec_ptn[PARTITION_MAX_NUM];
//partition need to erase
rec_partition erase_ptn[PARTITION_MAX_NUM];

/*
const char *need_head_ptn[] = {"default-mac", "pin", "product-info", "partition-table",
								"soft-version", "support-list", "profile", "default-config",
								"user-config", "NULL"};*/

const char *need_head_ptn[] = {"partition-table", "NULL"};
const char *need_erase_ptn[] = {"uboot-env", "user-config", "log", "NULL"};

unsigned int par_table_base;
/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/
/*
 *\fn           pth_need_head
 *\brief        check if the partition need head buff
 *
 *\param[in]    name   the partition name to check
 *\param[out]   N/A
 *
 *\return       1:need head,0:not need
 */
static int pth_need_head(const char *name)
{
	int i = 0;

	while (1)
	{
		if(strcmp(need_head_ptn[i], "NULL") == 0)
			return 0;
		if(strcmp(need_head_ptn[i], name) == 0)
			return 1;
		i++;
	}
}
/*
 *\fn           get_ptn_len_with_head
 *\brief        calculate the valid length of the partition
 *
 *\param[in]    name   the partition to calculate
 *              buf    the buff contains the partition information
 *\param[out]   N/A
 *
 *\return       the valid length of partition
 */
static unsigned int get_ptn_len_with_head(const char *name, const unsigned char *buf)
{
	int i = 0;

	if(strcmp(name, "partition-table") == 0)
		i = 4;
	while(buf[i] != '\0')
		i++;
	return i + 1;
}
/*
 *\fn           find_partition
 *\brief        find the needed partition
 *
 *\param[in]    recp   the sturct contains the partitions information
 *              index  the index of found partition,or the unused index if partition not found
 *              name   the partition to find
 *\param[out]   N/A
 *
 *\return       1:partition found,0:partition not found
 */
static int find_partition(rec_partition *recp, int *index, const char *name)
{
	int i;
	for (i = 0;i < PARTITION_MAX_NUM;i++)
	{
		if(recp[i].name[0] == '\0')
		{
			*index = i;
			return 0;
		}
		if (strcmp(recp[i].name, name) == 0)
		{
			*index = i;
			return 1;
		}
	}
	return 0;
}
/*
 *\fn           get_update_partition
 *\brief        get the information of partitions needed to update
 *
 *\param[in]    recp   the sturct contains the partitions information
 *              buf    the buff contains the partition information
 *              len    the length of buff
 *\param[out]   N/A
 *
 *\return       the num of partitions
 */
static int get_update_partition(rec_partition *recp, const unsigned char *buf, unsigned int len)
{
	int argc, i;
	char *argv[PARTITION_MAX_NUM * 8];
	int ret = 0;
	int index = -1;

	argc = rec_str_split(buf, len, " \r\n\t", argv, PARTITION_MAX_NUM * 8);
	if (argc == 0)
	{
		REC_ERROR("wrong update partition data");
		goto err_out;
	}
	for (i = 0;i < argc;i++)
	{
		if (strcmp(argv[i], "fwup-ptn") == 0)
		{
			i++;
			index = -1;
			ret = find_partition(recp, &index, argv[i]);
			if (ret == 1)
			{
				REC_ERROR("one or more same update partition found");
				ret = 0;
				goto err_out;
			}
			if (ret == 0 && index == -1)
			{
				REC_ERROR("too many update partition");
				ret = 0;
				goto err_out;
			}
			memcpy(recp[index].name, argv[i], strlen(argv[i]) + 1);
			recp[index].need_head = pth_need_head(recp[index].name);
		}
		else if (strcmp(argv[i], "base") == 0)
		{
			i++;
			recp[index].datastart = hextoint(argv[i]);
		}
		else if (strcmp(argv[i], "size") == 0)
		{
			i++;
			recp[index].datalen = hextoint(argv[i]);
			if(recp[index].need_head == 1)
				recp[index].need_head = get_ptn_len_with_head(recp[index].name, buf + recp[index].datastart);
		}
		else
		{
			REC_ERROR("unrecognized value \"%s\" found", argv[i]);
			ret = 0;
			goto err_out;
		}
	}
	ret = index + 1;
err_out:
	for (i = 0;i < argc;i++)
		free(argv[i]);
	return ret;
}
/*
 *\fn           get_partition
 *\brief        get the information of base in flash of partitions needed to update
 *
 *\param[in]    recp   the sturct contains the partitions information
 *              buf    the buff contains the partition information
 *              len    the length of buff
 *\param[out]   N/A
 *
 *\return       the num of found partitions
 */
static int get_partition(rec_partition *recp, const unsigned char *buf, unsigned int len)
{
	int argc, i;
	char *argv[PARTITION_MAX_NUM * 8];
	int ret;
	int index = -1;
	int num = 0;

	argc = rec_str_split(buf, len, " \r\n\t", argv, PARTITION_MAX_NUM * 8);
	if (argc == 0)
	{
		REC_ERROR("wrong partition data");
		goto err_out;
	}
	for (i = 0;i < argc;i++)
	{
		if (strcmp(argv[i], "partition") == 0)
		{
			i++;
			index = -1;
			ret = find_partition(recp, &index, argv[i]);
			if (ret == 0)
			{
				index = -1;
				continue;
			}
			i++;
			num++;
		}
		if(index == -1)
			continue;
		if (strcmp(argv[i], "base") == 0)
		{
			i++;
			recp[index].base = hextoint(argv[i]);
		}
		else if (strcmp(argv[i], "size") == 0)
		{
			i++;
			recp[index].size = hextoint(argv[i]);
		}
		else
		{
			REC_ERROR("unrecognized value \"%s\" found", argv[i]);
			goto err_out;
		}
	}
err_out:
	for (i = 0;i < argc;i++)
		free(argv[i]);
	return num;
}
static int check_supportlist(const unsigned char *buf)
{
	//partition containing product info
	rec_partition product_info_ptn[2];
	const char *product_ptn = "product-info";

	int i, j, k, index;
	int ret = 0;

	unsigned char *buf_product;

	int argc_list;
	int argc_product;
	int argc;
	char *argv_list[SUPPORT_LIST_MAX_NUM];
	char *argv_product[PRODUCT_INFO_MAX_NUM * 2];
	char *argv[PRODUCT_INFO_MAX_NUM * 2];

	//check if support-list partition exist
	if (find_partition(rec_ptn, &index, "support-list") == 0)
	{
		REC_DEBUG("do not consist support-list partition,all hardware can recovery");
		return 1;
	}
	//get product_info partition base and size
	memset(product_info_ptn, 0, 2 * sizeof(rec_partition));
	memcpy(product_info_ptn[0].name, product_ptn, strlen(product_ptn));
	if (get_partition(product_info_ptn, buf + IMAGE_SIZE_BASE + par_table_base + 4, IMAGE_INDEX_SIZE) != 1)
	{
		REC_DEBUG("get product_info failed");
		return 0;
	}

	//read support list
	argc_list = rec_str_split(buf + IMAGE_SIZE_BASE + rec_ptn[index].datastart + 8, rec_ptn[index].datalen - 8,
		"{}\r\n", argv_list, SUPPORT_LIST_MAX_NUM);
	if (argc_list == 0 || strcmp(argv_list[0], "SupportList:") != 0)
	{
		REC_ERROR("wrong support-list data");
		ret = 0;
		goto err_out2;
	}
	//read product_info
	buf_product = malloc(product_info_ptn[0].size);
	ret = flash_read(product_info_ptn[0].base, product_info_ptn[0].size, buf_product);
	if (ret)
	{
		REC_ERROR("flash read product info failed");
		ret = 0;
		goto err_out1;
	}
	argc_product = rec_str_split(buf_product + 8, product_info_ptn[0].size - 8,
		":\r\n", argv_product, PRODUCT_INFO_MAX_NUM * 2);
	if (argc_product == 0)
	{
		REC_ERROR("wrong product info data");
		ret = 0;
		goto err_out1;
	}
	//compare to check if support
	for (i = 1;i < argc_list;i++)
	{
		argc = rec_str_split(argv_list[i], strlen(argv_list[i]) + 1, ":,", argv, PRODUCT_INFO_MAX_NUM * 2);
		if (argc == 0)
		{
			REC_ERROR("parse support list failed");
			goto err_out1;
		}
		for (j = 0;j < argc;j = j + 2)
		{
			for (k = 0;k < argc_product;k = k + 2)
			{
				if(strcmp(argv_product[k], argv[j]) == 0)
					break;
			}
			if(k == argc_product)
				break;
			if(strcmp(argv_product[k + 1], argv[j + 1]) != 0)
				break;
		}
		for (k = 0;k < argc;k++)
			free(argv[k]);
		if(j == argc)
		{
			ret = 1;
			break;
		}
	}
	if(i == argc_list)
		ret = 0;
err_out1:
	free(buf_product);
	for (i = 0;i < argc_product;i++)
		free(argv_product[i]);
err_out2:
	for (i = 0;i < argc_list;i++)
		free(argv_list[i]);
out:
	return ret;
}
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
int recovery(unsigned int addr)
{
	unsigned char *buf;
	unsigned char md5[MD5_LEN];
	unsigned int len;
	unsigned int erase_base;
	unsigned int erase_size;
	unsigned char headbuf[8];
	int ret = 0;
	int i;
	int index;
	int num_up;

	//init the flashIO
	ret = flash_probe();
	if (ret)
	{
		REC_ERROR("flshIO init failed");
		goto err_out2;
	}
	//check image size
	buf = (unsigned char *)addr;
	memcpy(&len, buf, IMAGE_SIZE_LEN);
	len = ntohl(len);
	if (len < IMAGE_SIZE_MIN || len > IMAGE_SIZE_MAX)
	{
		REC_ERROR("invlalid image length \"%X\"", len);
		ret = 1;
		goto err_out2;
	}
	REC_DEBUG("image size :%X", len);

	//check md5
	memcpy(md5, buf + IMAGE_SIZE_LEN, MD5_LEN);
	memcpy(buf + IMAGE_SIZE_LEN, md5ImageKey, MD5_LEN);
	ret = check_Md5(md5, buf + IMAGE_SIZE_LEN, len - IMAGE_SIZE_LEN);
	if (ret != 1)
	{
		REC_ERROR("wrong md5 found");
		ret = 1;
		goto err_out;
	}
	REC_DEBUG("md5 checked");

	//get update partition
	memset(rec_ptn, 0, PARTITION_MAX_NUM * sizeof(rec_partition));
	ret = get_update_partition(rec_ptn, buf + IMAGE_SIZE_BASE, IMAGE_UPDATE_INDEX_SIZE);
	if (ret == 0)
	{
		ret = 1;
		goto err_out;
	}
	num_up = ret;
	REC_DEBUG("update partition got");

	//get partition-table base
	if (find_partition(rec_ptn, &index, "partition-table") == 0)
	{
		REC_DEBUG("can not find partition-table");
		ret = 1;
		goto err_out;
	}
	par_table_base = rec_ptn[index].datastart;

	//check support_list
	if (check_supportlist(buf) == 0)
	{
		REC_DEBUG("this image do not match the hardware,now restart");
		ret = 1;
		goto err_out;
	}

	//get partition
	if (ret != get_partition(rec_ptn, buf + IMAGE_SIZE_BASE + par_table_base + 4, IMAGE_INDEX_SIZE))
	{
		REC_ERROR("not enough partition data for recovery");
		ret = 1;
		goto err_out;
	}
	REC_DEBUG("partition got");

	//get erase base and size
	memset(erase_ptn, 0, PARTITION_MAX_NUM * sizeof(rec_partition));
	ret = 0;
	while (strcmp(need_erase_ptn[ret], "NULL") != 0)
	{
		memcpy(erase_ptn[ret].name, need_erase_ptn[ret], strlen(need_erase_ptn[ret]));
		ret ++;
	}
	if (ret != get_partition(erase_ptn, buf + IMAGE_SIZE_BASE + par_table_base + 4, IMAGE_INDEX_SIZE))
	{
		REC_ERROR("not enough erase partition data for recovery");
		ret = 1;
		goto err_out;
	}
	REC_DEBUG("erase partition got");
	for (i = 0;i < ret;i++)
	{
		REC_DEBUG("partirion \"%s\",base 0x%X,size 0x%X erasing",
			erase_ptn[i].name, erase_ptn[i].base, erase_ptn[i].size);
		flash_erase(erase_ptn[i].base, erase_ptn[i].size);
		REC_DEBUG("erase done!!!!!!!!!");
	}
	

	//write update partition to flash
	for (i = 0;i < num_up;i++)
	{
		REC_DEBUG("partirion \"%s\",base 0x%X,size 0x%X erasing",
			rec_ptn[i].name, rec_ptn[i].base, rec_ptn[i].size);
		flash_erase(rec_ptn[i].base, rec_ptn[i].size);
		REC_DEBUG("erase done!!!!!!!!!");
		REC_DEBUG("partirion \"%s\",base 0x%X,size 0x%X,start 0x%X,data 0x%X writing",
			rec_ptn[i].name, rec_ptn[i].base, rec_ptn[i].size,rec_ptn[i].datastart, rec_ptn[i].datalen);
		memset(headbuf, 0, 8);
		if (rec_ptn[i].need_head > 0)
		{
			len = htonl(rec_ptn[i].need_head);
			memcpy(headbuf, &len, 4);
			flash_write(rec_ptn[i].base, 8, headbuf);
			flash_write(rec_ptn[i].base + 8, rec_ptn[i].datalen, buf + rec_ptn[i].datastart + IMAGE_SIZE_BASE);
		}
		else
			flash_write(rec_ptn[i].base, rec_ptn[i].datalen, buf + rec_ptn[i].datastart + IMAGE_SIZE_BASE);
		REC_DEBUG("partirion write done,head:%2X,%2X,%2X,%2X", headbuf[0], headbuf[1], headbuf[2], headbuf[3]);
	}
	REC_DEBUG("recovery done!!!!!!!!!");
	ret = 0;

err_out:
	free(buf);
err_out2:
	return ret;
}
/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/
unsigned int get_tplink_machine_type()
{
    rec_partition product_info_ptn[2];
    const char *product_ptn = "product-info";
    static int machine_type = -1;

    int i;
    int ret = 0;
    int len = 0;
    int blank = 0;
    int partition_addr = 0x1f00000;
    unsigned char *buf_product = NULL;
    unsigned char *buf_partition = NULL;
    int argc_product = 0;
    char *argv_product[PRODUCT_INFO_MAX_NUM * 2];

    if (machine_type != -1) {
    	ret = machine_type;
		goto err_out;
	}

	if (flash_probe() || flash_read(partition_addr, 0x4, &len)
        || flash_read(partition_addr + 4, 0x4, &blank)) {
		goto err_out;
	}
    len = ntohl(len);
    if (blank != 0 || len < 0 || len > 0x10000) {
    	goto err_out;
	}

	buf_partition = malloc(len);
	if (!buf_partition || flash_read(partition_addr + 8, len, buf_partition)) {
		goto err_out;
	}

	memset(product_info_ptn, 0, 2 * sizeof(rec_partition));
	memcpy(product_info_ptn[0].name, product_ptn, strlen(product_ptn));
	if (get_partition(product_info_ptn, buf_partition + 4, IMAGE_INDEX_SIZE) != 1) {
		goto err_out;
	}

	if (product_info_ptn[0].size < len) {
        buf_product = buf_partition;
        buf_partition = NULL;
    } else {
        buf_product = malloc(product_info_ptn[0].size);
    }

	if (!buf_product || flash_read(product_info_ptn[0].base, product_info_ptn[0].size, buf_product)) {
		goto err_out;
	}

	argc_product = rec_str_split(buf_product + 8, product_info_ptn[0].size - 8,
		":\r\n", argv_product, PRODUCT_INFO_MAX_NUM * 2);
	if (argc_product == 0) {
		goto err_out;
	}

	for (i = 0; i < argc_product; i = i + 2) {
		if (strcmp(argv_product[i], "product_id") == 0) {
            ret = simple_strtoul(argv_product[i + 1], NULL, 16);
			break;
        }
	}

err_out:
	if (buf_partition)
        free(buf_partition);
    if (buf_product)
        free(buf_product);
	for (i = 0;i < argc_product;i++)
		free(argv_product[i]);
out:
    machine_type = ret;
	return ret;
}

