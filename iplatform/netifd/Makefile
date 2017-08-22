include $(TOPDIR)/rules.mk

PKG_NAME:=netifd
PKG_VERSION:=2013-05-13
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://nbd.name/luci2/netifd.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=bc4a4bb127622c76085ecec7fd20448aad7bafaf
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=Felix Fietkau <nbd@openwrt.org>
# PKG_MIRROR_MD5SUM:=
# CMAKE_INSTALL:=1

PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=

PKG_BUILD_PARALLEL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/netifd
  SECTION:=base
  # CATEGORY:=Base system
  CATEGORY:=TP-LINK iplatform apps
  SUBMENU:=Network
  DEPENDS:=+libuci +libnl-tiny +libubus +ubus +ubusd +jshn +kmod-bonding
  TITLE:=OpenWrt Network Interface Configuration Daemon
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(STAGING_DIR)/usr/include

CMAKE_OPTIONS += \
	-DLIBNL_LIBS=-lnl-tiny \
	-DDEBUG=1 -DKEEP_BRIDGE=1

# arm: CONFIG_arm=y
# mips: CONFIG_mips=y
ifneq ($(CONFIG_arm),)
	CMAKE_OPTIONS += -D__ARM__=1
endif

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/netifd/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/netifd $(1)/sbin/
	$(CP) ./filesystem/* $(1)/
	$(CP) $(PKG_BUILD_DIR)/dummy/netifd-proto.sh $(1)/lib/netifd/
endef

$(eval $(call BuildPackage,netifd))
