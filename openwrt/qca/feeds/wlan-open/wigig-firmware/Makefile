#
# Copyright (c) 2014 The Linux Foundation. All rights reserved.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wigig-firmware
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_RELEASE:=1

include $(INCLUDE_DIR)/local-development.mk

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=QCA wigig(wil6210,11ad) firmware
endef

define Package/$(PKG_NAME)/description
  This package contains the wigig(wil61210,11ad) Firmware binaries
endef

Build/Compile=true

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/lib/firmware
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/WIL6210/wil6210.fw \
	$(1)/lib/firmware/
	$(INSTALL_DATA) \
		$(PKG_BUILD_DIR)/WIL6210/wil6210.board \
	$(1)/lib/firmware/wil6210.brd
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
