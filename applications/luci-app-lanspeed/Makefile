include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-lanspeed
PKG_VERSION:=1.1.2
PKG_RELEASE:=1

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
  DEPENDS:=+lanspeedd +lanspeedd-bpf +luci-base
endef

define Package/luci-app-lanspeed/description
 LuCI real-time status and settings page for lanspeedd. Displays per-client
 upload, download and current TCP / UDP connections, configures interfaces as
 collect / observe / off, and provides a dedicated diagnostics page for
 concise plugin, backend and BPF health with only actionable alerts.
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
	$(INSTALL_DATA) \
		./htdocs/luci-static/resources/view/lanspeed/config.js \
		./htdocs/luci-static/resources/view/lanspeed/diagnostics.js \
		./htdocs/luci-static/resources/view/lanspeed/overview.js \
		$(1)/www/luci-static/resources/view/lanspeed/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/lanspeed
	$(INSTALL_DATA) \
		./htdocs/luci-static/resources/lanspeed/configForm.js \
		./htdocs/luci-static/resources/lanspeed/configModel.js \
		./htdocs/luci-static/resources/lanspeed/configStyle.js \
		./htdocs/luci-static/resources/lanspeed/configStyleArgon.js \
		./htdocs/luci-static/resources/lanspeed/configStyleAurora.js \
		./htdocs/luci-static/resources/lanspeed/configStyleBase.js \
		./htdocs/luci-static/resources/lanspeed/configStyleBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/configStyleResponsive.js \
		./htdocs/luci-static/resources/lanspeed/configStyleShared.js \
		./htdocs/luci-static/resources/lanspeed/configView.js \
		./htdocs/luci-static/resources/lanspeed/designSystem.js \
		./htdocs/luci-static/resources/lanspeed/designSystemArgon.js \
		./htdocs/luci-static/resources/lanspeed/designSystemAurora.js \
		./htdocs/luci-static/resources/lanspeed/designSystemBase.js \
		./htdocs/luci-static/resources/lanspeed/designSystemBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsRefresh.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsShell.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyle.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyleArgon.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyleAurora.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyleBase.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyleBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsStyleResponsive.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsModel.js \
		./htdocs/luci-static/resources/lanspeed/diagnosticsView.js \
		./htdocs/luci-static/resources/lanspeed/clientConnections.js \
		./htdocs/luci-static/resources/lanspeed/dhcpHostnames.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailShell.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyle.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleBase.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleArgon.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleAurora.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleResponsive.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailRefresh.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailView.js \
		./htdocs/luci-static/resources/lanspeed/format.js \
		./htdocs/luci-static/resources/lanspeed/geoLocation.js \
		./htdocs/luci-static/resources/lanspeed/ifaceConfig.js \
		./htdocs/luci-static/resources/lanspeed/rpc.js \
		./htdocs/luci-static/resources/lanspeed/statusCollector.js \
		./htdocs/luci-static/resources/lanspeed/statusIp.js \
		./htdocs/luci-static/resources/lanspeed/statusRefresh.js \
		./htdocs/luci-static/resources/lanspeed/statusShell.js \
		./htdocs/luci-static/resources/lanspeed/statusStyle.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleArgon.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleAurora.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleBase.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleResponsive.js \
		./htdocs/luci-static/resources/lanspeed/statusOverview.js \
		./htdocs/luci-static/resources/lanspeed/statusView.js \
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
