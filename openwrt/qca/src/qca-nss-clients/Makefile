# Makefile for the clients using the NSS driver

ccflags-y := -I$(obj) -I$(obj)/..

ifneq ($(findstring 3.4, $(KERNELVERSION)),)
obj-m += qca-nss-tunipip6.o
obj-m += qca-nss-ipsecmgr.o

ifeq "$(CONFIG_IPV6_SIT_6RD)" "y"
obj-m += qca-nss-tun6rd.o
qca-nss-tun6rd-objs := nss_connmgr_tun6rd.o
ccflags-y += -DNSS_TUN6RD_DEBUG_LEVEL=0
endif

qca-nss-tunipip6-objs := nss_connmgr_tunipip6.o
ccflags-y += -DNSS_TUNIPIP6_DEBUG_LEVEL=0
qca-nss-ipsecmgr-objs := nss_ipsecmgr.o
ccflags-y += -DNSS_IPSECMGR_DEBUG_LEVEL=3
endif

obj-y+= profiler/

ifneq ($(findstring 3.4, $(KERNELVERSION)),)
obj-y+= nss_qdisc/
obj-y+= capwapmgr/
endif

obj ?= .

