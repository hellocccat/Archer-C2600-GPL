#
# Copyright (C) 2013 Shenzhen TP-LINK Technologies Co.Ltd.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=prebuilt
PKG_VERSION:=1

include $(INCLUDE_DIR)/toolchain-build.mk

ifeq ($(call qstrip, $(CONFIG_PREBUILT_TOOLCHAIN_DIR)),)
CONFIG_PREBUILT_TOOLCHAIN_DIR="$(TOPDIR)/dl"
endif

ifeq ($(call qstrip,$(CONFIG_PREBUILT_TOOLCHAIN_ARCHIVE)),)
CONFIG_PREBUILT_TOOLCHAIN_ARCHIVE="$(CONFIG_PREBUILT_TOOLCHAIN_DIR)/toolchain-$(ARCH)$(ARCH_SUFFIX)_gcc-$(GCCV)$(DIR_SUFFIX)-$(shell uname -m).tar.gz"
endif

PKG_SOURCE:=$(call qstrip,$(CONFIG_PREBUILT_TOOLCHAIN_ARCHIVE))

TOOLCHAIN_UNPACK=tar xf $(PKG_SOURCE) -C $(TOOLCHAIN_DIR)/..

define Host/Prepare
endef

define Host/Configure
endef

define Host/Compile
endef

define Host/Install
	$(TOOLCHAIN_UNPACK)
	mkdir -p $(TOPDIR)/staging_dir/target-arm_v7-a$(DIR_SUFFIX)/usr/include
	echo "#define log(proj_id, msg_id, ...)" > $(TOPDIR)/staging_dir/target-arm_v7-a$(DIR_SUFFIX)/usr/include/log.h
	echo "#define LOG(msg_id, ...)" >> $(TOPDIR)/staging_dir/target-arm_v7-a$(DIR_SUFFIX)/usr/include/log.h
endef

define Host/Clean
	rm -rf $(TOOLCHAIN_DIR)
endef

$(eval $(call HostBuild))
