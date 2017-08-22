include $(TOPDIR)/rules.mk

PKG_NAME:=jquery-contextmenu
PKG_SOURCE_URL:=https://www.codeaurora.org/mirrored_source/quic/qsdk/
PKG_BRANCH:=master
PKG_RELEASE:=1
PKG_VERSION:=1.01

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-gecb2ce1.tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-gecb2ce1
PKG_MD5SUM:=68bea4fe66f2532644c754a7ddcf7268

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/jquery-contextmenu
  SECTION:=language-javascript
  CATEGORY:=Languages
  SUBMENU:=JavaScript
  TITLE:=jQuery context menu
  URL:=http://abeautifulsite.net/2008/09/jquery-context-menu-plugin/
  DEPENDS:=+jquery
endef

define Package/jquery-contextmenu/description
	A jquery context menu plugin
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/jquery-contextmenu/install
	$(INSTALL_DIR) $(1)/www/js/
	$(INSTALL_DIR) $(1)/www/css/
	cp $(PKG_BUILD_DIR)/js/jquery.contextMenu.js $(1)/www/js/
	cp $(PKG_BUILD_DIR)/css/jquery.contextMenu.css $(1)/www/css/
endef

$(eval $(call BuildPackage,jquery-contextmenu))
