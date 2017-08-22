/*! Copyright(c) 2008-2014 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     connect.h
 *\brief        
 *\details  
 *
 *\author   Zhu Xianfeng<zhuxianfeng@tp-link.net>
 *\version  1.0.0
 *\date     29May14
 *
 *\warning  
 *
 *\history \arg 29May14, Zhu Xianfeng, create the file.
 */
#ifndef __CONNECT_H__
#define __CONNECT_H__

#include <libubox/blob.h>

int connect_init();
void connect_exit();
void connect_dump_info(struct blob_buf *b);

#endif
