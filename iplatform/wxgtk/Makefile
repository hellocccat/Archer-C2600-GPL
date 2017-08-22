#
# Copyright (C) 2012-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=wxgtk
PKG_VERSION:=2.8.12
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

define Package/$(PKG_NAME)/config
#  source "$(SOURCE)/Config.in"
endef

define Package/$(PKG_NAME)
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
#  SUBMENU:=amule
  TITLE:=A c++ frame library
  DEPENDS:=+zlib +libstdcpp +libpthread
endef

define Package/$(PKG_NAME)/description
 wxgtk is a c++ based library for amule
endef

CONFIGURE_ARGS += \
		   --enable-unicode \
           --disable-shared \
           --without-subdirs \
           --disable-gui \
           --disable-debugreport \
           --enable-no_deps \
           --disable-gtktest \
           --disable-sdltest \
           --disable-geometry \
           --disable-debug \
           --disable-debug_flag \
           --disable-debug_info \
           --enable-optimise \
           --disable-mem_tracing \
           --disable-no_rtti \
           --enable-intl \
		   --disable-catch_segvs \
		   --disable-no_exceptions \
		   --disable-exceptions \
		   --enable-backtrace \
		   --enable-largefile \
		   \
		   --without-gtk \
		   --without-motif \
		--without-mac \
		--without-cocoa \
		--without-wine \
		--without-msw \
		--without-pm \
		--without-mgl \
		--without-microwin \
		--without-x11 \
		--without-libpng \
		--without-libjpeg \
		--without-libtiff \
		--without-libxpm \
		--without-libmspack \
		--without-sdl \
		--without-gnomeprint \
		--without-opengl \
		--without-dmalloc \
		--with-zlib="sys" \
		--without-odbc \
		--without-expat \
		--without-gtk-prefix \
		--without-x \
		--without-libiconv-prefix \
		--without-sdl-prefix \
		--without-cppunit-prefix

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile	
	$(call Build/Compile/Default)
endef

define Build/Install    
	$(call Build/Install/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/include $(1)/usr/lib
	$(CP) -L $(PKG_BUILD_DIR)/wx-config $(1)/usr/bin/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/wx-2.8 $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwx_base* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/wx $(1)/usr/lib/
	$(SED) 's,-I$$$${includedir}/wx-2.8,-I$(STAGING_DIR)/usr/include/wx-2.8,g' $(1)/usr/bin/wx-config
	$(SED) 's,-I$$$${libdir}/wx/include,-I$(STAGING_DIR)/usr/lib/wx/include,g' $(1)/usr/bin/wx-config
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	#$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwx*.so* $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwx*.a $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
