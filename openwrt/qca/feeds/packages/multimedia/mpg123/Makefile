#
# Copyright (c) 2012 The Linux Foundation. All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mpg123
PKG_VERSION:=1.14.4
PKG_RELEASE:=1

PKG_SOURCE:=mpg123-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@SF/mpg123
PKG_MD5SUM:=a72d0c60a1d7dbec7cfe966bc11672bf

PKG_BUILD_DIR:=$(BUILD_DIR)/mpg123-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

PKG_INSTALL=1

CONFIGURE_ARGS += --enable-shared \
                  --enable-static

define Package/mpg123/Default
  URL:=http://mpg123.sourceforge.net/
endef

define Package/libmpg123
  $(call Package/mpg123/Default)
  SECTION:=multimedia
  CATEGORY:=Multimedia
  TITLE:=Fast console MPEG Audio Player and decoder library
  DEPENDS:=+libltdl +alsa-lib
endef
define Package/libmpg123/description
  This is the fast and Free (LGPL license) real time MPEG Audio
  Layer 1, 2 and 3 decoding library and console player.
  It uses floating point or integer math, along with several
  special optimizations (3DNow, SSE, ARM, ...) to make it most efficient.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) \
		$(PKG_INSTALL_DIR)/usr/include/mpg123.h \
		$(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/libmpg123.{la,a,so*} \
		$(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/pkgconfig/libmpg123.pc \
		$(1)/usr/lib/pkgconfig
endef
define Package/libmpg123/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libmpg123.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libmpg123))
