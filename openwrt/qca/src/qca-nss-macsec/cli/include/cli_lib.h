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

#ifndef __CLI_PARSE_LIB_H__
#define __CLI_PARSE_LIB_H__

#include <sys_base.h>
#include "array.h"

#define CLI_MAC_STR_LEN_MAX     14	/* aaaa.bbbb.cccc */
#define CLI_MAC_STR_LEN_MIN     5	/* 1.1.1 */

#define CLI_IPV4_STR_LEN_MAX    15	/* aaa.bbb.ccc.ddd */
#define CLI_IPV4_STR_LEN_MIN    7	/* a.b.c.d */

#define CLI_IPV6_STR_LEN_MAX    39	/* xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx */
#define CLI_IPV6_STR_LEN_MIN    2	/* :: */

#define cli_str_2_enable(str) (strncmp(str, "enable", 1) == 0) ? 1 : 0
#define cli_enable_2_str(enable) enable? "enable" : "disable"

typedef struct {
	sa_u32_t flag;
	char *str;
	int cmp;
} flag_desc_t;

int cli_str_2_hex(const char *str, sa_u32_t * pHex);

int cli_str_2_mac(const char *str, sa_u8_t * mac);

int cli_mac_2_str(const sa_u8_t * mac, char *str);

int cli_u8_array_2_str(const sa_u8_t * array, int arrayNum, char *str,
		       int strLen);
/*
int cli_str_2_u8_array(const char *str, sa_u8_t *array, int *pArrayNum);
*/
int cli_str_2_ipv4(const char *str, sa_u8_t * ip);

int cli_ipv4_2_str(const sa_u8_t * ipv4, char *str);

int cli_str_2_ipv6(const char *str, sa_u8_t * ip);

int cli_ipv6_2_str(const sa_u8_t * ipv6, char *str);

int cli_str_2_list(const char *str, const sa_u32_t min, const sa_u32_t max,
		   ARRAY_T * pPortArray);

int cli_list_2_str(const sa_u32_t * list, const int num, char *str);

int cli_uint64_2_dec_str(sa_u64_t * num, char *str);

int cli_uint64_2_hex_str(sa_u64_t * num, char *str);

int cli_str_2_sci(const char *str, sa_u8_t * sci);

int cli_sci_2_str(const sa_u8_t * sci, char *str);

int cli_str_2_sak(const char *str, sa_u8_t * key);

int cli_sak_2_str(const sa_u8_t * key, char *str, int strLen);

int cli_str_2_flag(const char *str, sa_u32_t * value, flag_desc_t * desc,
		   int desc_len);

int cli_flag_2_str(char *str, sa_u32_t value, flag_desc_t * desc, int desc_len);

int cli_str_2_value(const char *str, sa_u32_t * value, flag_desc_t * desc,
		    int desc_len);

int cli_value_2_str(char *str, sa_u32_t value, flag_desc_t * desc,
		    int desc_len);

#endif
