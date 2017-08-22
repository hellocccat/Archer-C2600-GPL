#
# Copyright (C) 2012-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=aria2
#PKG_VERSION:=1.18.4
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
#PKG_SOURCE_URL:=@SF/aria2
#PKG_MD5SUM:=d10fc5ee6e708760134e4cb963ecc98e
#PKG_INSTALL:=1

#PKG_MAINTAINER:=Imre Kaloz <kaloz@openwrt.org>
#PKG_LICENSE:=GPLv2
#PKG_LICENSE_FILES:=COPYING

PKG_CONFIG_DEPENDS := \
  ARIA2_NOSSL \
  ARIA2_OPENSSL \
  ARIA2_GNUTLS \
  ARIA2_BITTORRENT \
  ARIA2_METALINK

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

define Package/aria2/config
  source "$(SOURCE)/Config.in"
endef

define Package/aria2
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
#  SUBMENU:=Download Proxy
  TITLE:=lightweight download utility
  DEPENDS:=+zlib +ARIA2_METALINK:libxml2 +libstdcpp +ARIA2_OPENSSL:libopenssl +ARIA2_GNUTLS:libgnutls
endef

define Package/aria2/description
 aria2 is a lightweight multi-protocol & multi-source command-line download
 utility
endef

CONFIGURE_ARGS += \
	--disable-nls \
	$(if $(CONFIG_ARIA2_NOSSL),--disable,--enable)-ssl \
	$(if $(CONFIG_ARIA2_OPENSSL),--with,--without)-openssl \
	$(if $(CONFIG_ARIA2_GNUTLS),--with,--without)-gnutls \
	$(if $(CONFIG_ARIA2_BITTORRENT),--enable,--disable)-bittorrent \
	$(if $(CONFIG_ARIA2_METALINK),--enable,--disable)-metalink \
	$(if $(CONFIG_ARIA2_METALINK),--with,--without)-libxml2 \
	--without-libnettle \
	--without-libgmp \
	--without-libgcrypt \
	--without-libexpat \
	--without-libcares \
	--without-sqlite3 \
	--with-libz

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -u ./src/* $(PKG_BUILD_DIR)/
endef

define Package/aria2/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/aria2c $(1)/usr/bin/aria2c
#	$(INSTALL_DIR) $(1)/www/download
#	$(INSTALL_DIR) $(1)/www/download/css
#	$(INSTALL_DIR) $(1)/www/download/js
#	$(INSTALL_DIR) $(1)/www/download/img
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/download/index.html       $(1)/www/download
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/download/offline.appcache $(1)/www/download
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/download/css/*            $(1)/www/download/css/
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/download/js/*             $(1)/www/download/js/
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/download/img/*            $(1)/www/download/img/	
#	$(INSTALL_DIR) $(1)/etc/config
#	$(INSTALL_BIN) ./filesystem/etc/config/aria2 $(1)/etc/config/aria2
#	$(INSTALL_BIN) ./filesystem/etc/config/aria2 $(1)/etc/config/aria2
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./filesystem/etc/init.d/aria2 $(1)/etc/init.d/aria2
	$(INSTALL_BIN) ./filesystem/etc/init.d/offline_download $(1)/etc/init.d/offline_download
endef

$(eval $(call BuildPackage,aria2))
