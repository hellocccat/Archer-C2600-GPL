#
# Copyright (C) 2006-2012 OpenWrt.org
# Copyright (C) 2010 Vertical Communications
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=block-mount
PKG_VERSION:=0.2.0
PKG_RELEASE:=9

include $(INCLUDE_DIR)/package.mk

define Package/block-mount/Default
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
  SUBMENU:=Base system
endef

define Package/block-mount
  $(call Package/block-mount/Default)
  TITLE:=Block device mounting and checking
  DEPENDS:= +blkid +swap-utils 
  MENU:=1
endef

define Package/block-mount/description
  Scripts used to mount and check block devices (filesystems and swap), as well
  as hotplug scripts to automount and check block devices when hotplug event (e.g.
  from plugging in a device) occurs.
  Also includes preinit scripts for mounting a block device as the root filesystem.
  This allows one to have the root filesystem on devices other than the built in flash
  device.
endef

define Package/block-mount/config
	source "$(SOURCE)/Config.in"
endef

define Build/Compile
endef

define Package/block-mount/conffiles
/etc/config/fstab
endef

define Package/block-mount/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./filesystem/fstab.init $(1)/etc/init.d/fstab
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./filesystem/fstab.config $(1)/etc/config/fstab
	$(INSTALL_DIR) $(1)/lib/functions/fsck
	$(INSTALL_DATA) ./filesystem/mount.sh $(1)/lib/functions/
	$(INSTALL_DATA) ./filesystem/fsck.sh $(1)/lib/functions/
	$(INSTALL_DATA) ./filesystem/block.sh $(1)/lib/functions/
	$(INSTALL_DIR) $(1)/etc/hotplug.d/block
	$(INSTALL_DATA) ./filesystem/10-swap $(1)/etc/hotplug.d/block/
	$(INSTALL_DATA) ./filesystem/20-fsck $(1)/etc/hotplug.d/block/
	$(INSTALL_DATA) ./filesystem/40-mount $(1)/etc/hotplug.d/block/
	$(INSTALL_DATA) ./filesystem/extmount.sh $(1)/lib/functions/
	$(INSTALL_DIR) $(1)/lib/preinit
	$(INSTALL_DATA) ./filesystem/50_determine_usb_root $(1)/lib/preinit/
	$(INSTALL_DATA) ./filesystem/55_determine_extroot_sysupgrade $(1)/lib/preinit/
	$(INSTALL_DATA) ./filesystem/60_pivot_usb_root $(1)/lib/preinit/
	echo "extroot_settle_time=\"$(CONFIG_EXTROOT_SETTLETIME)\"" >$(1)/lib/preinit/00_extroot.conf
	$(INSTALL_DIR) $(1)/overlay
endef

$(eval $(call BuildPackage,block-mount))
