#
# Copyright (C) 2012-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=amule
PKG_VERSION:=2.3.1
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

define Package/$(PKG_NAME)
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
#  SUBMENU:=amule
  TITLE:=A download APP based on eDonkey protocol
  DEPENDS:=+zlib +libstdcpp +libtomcrypt +wxgtk +libpthread +ubus +libubox
endef

define Package/$(PKG_NAME)/description
 amule is a c++ based application for downloading
endef
CONFIGURE_ARGS += \
			--disable-monolithic \
			--disable-debug \
			--enable-optimize \
			--disable-upnp \
			--disable-nls \
			--disable-ed2k \
			--enable-amule-daemon \
			--enable-amulecmd \
			--with-toolkit=base \
			--enable-mmap=yes \
			\
			--disable-rpath \
			--with-wx-prefix="$(STAGING_DIR)/usr" \
			--with-crypto-prefix="$(STAGING_DIR)/usr" \
			--with-zlib="$(STAGING_DIR)/usr" 

CONFIGURE_VARS += LIBS="-lubox -lubus"

#TARGET_CXXFLAGS += -std=gnu99
TARGET_CFLAGS += -std=gnu99 -DENABLE_UBUS_RPC

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile	
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
#	$(call Build/Compile/Default)
endef

#define Build/Install   
#	$(call Build/Install/Default)
#	-$(STRIP) $(PKG_INSTALL_DIR)/usr/bin/amuled
#	-$(STRIP) $(PKG_INSTALL_DIR)/usr/bin/amulecmd	
#endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/amuled $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/amuled $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/lib
	$(CP) $(TOOLCHAIN_DIR)/lib/libstdc++.so.6.0.16 $(1)/lib/
	$(CP) $(TOOLCHAIN_DIR)/lib/libstdc++.so.6 $(1)/lib/
	$(CP) $(TOOLCHAIN_DIR)/lib/libstdc++.so $(1)/lib/
#	$(INSTALL_DIR) $(1)/etc/config
#	$(INSTALL_DATA) ./filesystem/etc/config/offline_download $(1)/etc/config/offline_download
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./filesystem/etc/init.d/offline_download $(1)/etc/init.d/offline_download
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
