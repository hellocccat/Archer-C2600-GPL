#
# Copyright (c) 2014 The Linux Foundation. All rights reserved.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=GobiSerial
PKG_SOURCE_URL:=https://www.codeaurora.org/patches/quic/gobi/Gobi3000/
PKG_VERSION:=2011-07-29-1026
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk

PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/usb-gobi-serial
  SUBMENU:=USB Support
  DEPENDS:=@TARGET_ipq806x +kmod-usb-serial
  TITLE:=Kernel USB driver for GobiNet
  FILES:= $(PKG_BUILD_DIR)/GobiSerial.ko
  AUTOLOAD:=$(call AutoLoad,82,GobiSerial)
endef

define KernelPackage/GobiSerial/Description
This package contains a USB driver for Gobi Serial 3000
endef

define Build/Prepare
	$(call Build/Prepare/Default)
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		modules
endef

$(eval $(call KernelPackage,usb-gobi-serial))

