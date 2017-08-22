#
# Copyright (C) 2012-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=libtomcrypt
PKG_VERSION:=1.17
PKG_RELEASE:=1

#PKG_INSTALL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

#PKG_CONFIG_DEPENDS := \
  OFFLINE_DOWNLOAD_NOSSL \
  OFFLINE_DOWNLOAD_OPENSSL \
  OFFLINE_DOWNLOAD_GNUTLS \
  OFFLINE_DOWNLOAD_BITTORRENT \
  OFFLINE_DOWNLOAD_METALINK

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/tommath
MAKE_FLAGS += INCPATH=/usr/include/tomcrypt

define Package/$(PKG_NAME)/config
#  source "$(SOURCE)/Config.in"
endef

define Package/$(PKG_NAME)
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
#  SUBMENU:=
  TITLE:=a light crypt library
  DEPENDS:=+libtommath
endef

define Package/$(PKG_NAME)/description
 libtommath is a c based crypt library
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile	
	$(call Build/Compile/Default)
endef

define Build/Install    
	(export NODOCS=y;$(call Build/Install/Default))
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/tomcrypt $(1)/usr/include

	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtomcrypt* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	#$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtomcrypt*.so* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtomcrypt*.a $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
