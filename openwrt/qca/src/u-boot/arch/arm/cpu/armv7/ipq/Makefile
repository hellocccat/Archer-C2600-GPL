# Copyright (c) 2012 The Linux Foundation. All rights reserved.

include $(TOPDIR)/config.mk
VPATH=./:./FirmwareRecovery
LIB	=  $(obj)lib$(SOC).o

SOBJS-y = timer.o
COBJS-y += clock.o
COBJS-y += gpio.o
COBJS-y += smem.o
COBJS-y += scm.o
COBJS-y += cmd_bootipq.o
SOBJS-y += cmd_firmrecovery.o flashIO.o Md5.o rec_lib.o recovery.o tftp.o
ifeq ($(CONFIG_IPQ_APPSBL_DLOAD),y)
COBJS-y += cmd_dumpipq_data.o
endif

SRCS	:= $(SOBJS-y:.o=.S) $(COBJS-y:.o=.c)
OBJS	:= $(addprefix $(obj),$(COBJS-y) $(SOBJS-y))

all:	 $(obj).depend $(LIB)

$(LIB):	$(OBJS)
	$(call cmd_link_o_target, $(OBJS))

#########################################################################

# defines $(obj).depend target
include $(SRCTREE)/rules.mk

sinclude $(obj).depend

#########################################################################

