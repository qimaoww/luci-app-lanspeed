include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-lanspeed
PKG_VERSION:=0.1.0
PKG_RELEASE:=8

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-lanspeed
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for LAN speed monitor
  PKGARCH:=all
  DEPENDS:=+lanspeedd +luci-base
endef

define Package/luci-app-lanspeed/description
 LuCI status and interface configuration page for lanspeedd. Reads per-client
 LAN speeds from the lanspeed ubus API and can update /etc/config/lanspeed
 interface assignments (collect / observe / off) and trigger a daemon reload.
 Respects the Full / Degraded / Unsupported data-source semantics reported by
 lanspeedd and surfaces coverage, confidence and NSS / offload state.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-lanspeed/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/lanspeed
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/lanspeed/*.js \
		$(1)/www/luci-static/resources/view/lanspeed/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/lanspeed
	$(INSTALL_DATA) ./htdocs/luci-static/resources/lanspeed/*.js \
		$(1)/www/luci-static/resources/lanspeed/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-lanspeed.json \
		$(1)/usr/share/luci/menu.d/luci-app-lanspeed.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-lanspeed.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-lanspeed.json
endef

$(eval $(call BuildPackage,luci-app-lanspeed))
