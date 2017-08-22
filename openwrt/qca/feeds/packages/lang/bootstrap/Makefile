include $(TOPDIR)/rules.mk

PKG_NAME:=bootstrap
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/twbs/bootstrap.git
PKG_BRANCH:=master
PKG_RELEASE:=v3.0.0

PKG_REV:=e8a1df5
PKG_VERSION:=0.1-g$(PKG_REV)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_MIRROR:=none
PKG_BUILD_PARALLEL:=0

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/bootstrap
  SECTION:=language-javascript
  CATEGORY:=Languages
  SUBMENU:=JavaScript
  TITLE:=Bootstrap
  URL:=http://http://getbootstrap.com/
endef

define Package/bootstrap/description
 Bootstrap web gui interface kit.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/bootstrap/install
	$(INSTALL_DIR) $(1)/www/js/
	cp $(PKG_BUILD_DIR)/dist/css/bootstrap-theme.min.css $(1)/www/css/
	cp $(PKG_BUILD_DIR)/dist/css/bootstrap.min.css $(1)/www/css/
	$(INSTALL_DIR) $(1)/www/css/
	cp $(PKG_BUILD_DIR)/dist/css/bootstrap.min.js $(1)/www/js/
	$(INSTALL_DIR) $(1)/www/fonts/
	cp $(PKG_BUILD_DIR)/dist/fonts/glyphicons-halflings-regular.eot $(1)/www/fonts/
	cp $(PKG_BUILD_DIR)/dist/fonts/glyphicons-halflings-regular.svg $(1)/www/fonts/
	cp $(PKG_BUILD_DIR)/dist/fonts/glyphicons-halflings-regular.ttf $(1)/www/fonts/
	cp $(PKG_BUILD_DIR)/dist/fonts/glyphicons-halflings-regular.woff $(1)/www/fonts/
endef

$(eval $(call BuildPackage,bootstrap))