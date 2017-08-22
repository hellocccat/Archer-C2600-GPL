#
# Copyright (c) 2013 The Linux Foundation. All rights reserved.
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bluez
PKG_VERSION:=4.99
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.kernel.org/pub/linux/bluetooth/
PKG_MD5SUM:=570aa10692ed890aa0a4297b37824912

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/bluez
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libpthread +dbus +glib2 $(INTL_DEPENDS) $(ICONV_DEPENDS)
  TITLE:=BlueZ stak (combined Lib and Utils)
  URL:=http://www.bluez.org/
endef

define Package/bluez/conffiles
/etc/bluetooth/rfcomm.conf
/etc/config/bluetooth
endef

CONFIGURE_ARGS += \
	--disable-glib \
	--enable-pand \
	--enable-rfcomm \
	--enable-dund \
	--enable-serial \
	--enable-network \
	--enable-usb \
	--enable-input \
	--disable-audio \
	--with-bluez="$(STAGING_DIR)/usr/include" \
	--with-usb=yes \

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LDFLAGS="$(TARGET_LDFLAGS) \
			-L$(ICONV_PREFIX)/lib \
			-L$(INTL_PREFIX)/lib -lm" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
endef

define Package/bluez/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/* $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/bluetooth
	$(CP) $(PKG_INSTALL_DIR)/etc/bluetooth/rfcomm.conf $(1)/etc/bluetooth/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/bluetooth.config $(1)/etc/config/bluetooth
	$(INSTALL_DIR) $(1)/etc/dbus-1/system.d/
	$(INSTALL_DATA) ./files/bluetooth.dbus $(1)/etc/dbus-1/system.d/bluetooth.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/bluez-utils.init $(1)/etc/init.d/bluez
endef

$(eval $(call BuildPackage,bluez))
