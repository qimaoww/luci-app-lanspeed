include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-lanspeed
PKG_VERSION:=0.1.7
PKG_RELEASE:=2

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
	$(INSTALL_DATA) \
		./htdocs/luci-static/resources/lanspeed/configForm.js \
		./htdocs/luci-static/resources/lanspeed/configStyle.js \
		./htdocs/luci-static/resources/lanspeed/format.js \
		./htdocs/luci-static/resources/lanspeed/ifaceConfig.js \
		./htdocs/luci-static/resources/lanspeed/nssPanel.js \
		./htdocs/luci-static/resources/lanspeed/rpc.js \
		./htdocs/luci-static/resources/lanspeed/statusCollector.js \
		./htdocs/luci-static/resources/lanspeed/statusIp.js \
		./htdocs/luci-static/resources/lanspeed/statusRefresh.js \
		./htdocs/luci-static/resources/lanspeed/statusShell.js \
		./htdocs/luci-static/resources/lanspeed/statusStyle.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleCompat.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleCompatLive.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleCompatLive2.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleCompatLive3.js \
		./htdocs/luci-static/resources/lanspeed/statusView.js \
		./htdocs/luci-static/resources/lanspeed/statusViewLive.js \
		./htdocs/luci-static/resources/lanspeed/statusViewLive2.js \
		./htdocs/luci-static/resources/lanspeed/statusViewLive3.js \
		./htdocs/luci-static/resources/lanspeed/theme.js \
		./htdocs/luci-static/resources/lanspeed/vocab.js \
		$(1)/www/luci-static/resources/lanspeed/
	printf "%s\n" \
		"'use strict';" \
		"'require baseclass';" \
		"" \
		"return baseclass.extend({" \
		"	PACKAGE_VERSION: '$(PKG_VERSION)'," \
		"	PACKAGE_RELEASE: '$(PKG_RELEASE)'," \
		"	FULL_VERSION: '$(PKG_VERSION)-r$(PKG_RELEASE)'" \
		"});" \
		> $(1)/www/luci-static/resources/lanspeed/version.js
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-lanspeed.json \
		$(1)/usr/share/luci/menu.d/luci-app-lanspeed.json
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-lanspeed.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-lanspeed.json
endef

$(eval $(call BuildPackage,luci-app-lanspeed))
