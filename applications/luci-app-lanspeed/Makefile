include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-lanspeed
PKG_VERSION:=1.0.0
PKG_RELEASE:=3

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
 collect / observe / off, and reports concise plugin, backend and BPF health
 with only actionable alerts.
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
		./htdocs/luci-static/resources/view/lanspeed/index.js \
		./htdocs/luci-static/resources/view/lanspeed/index_live7.js \
		$(1)/www/luci-static/resources/view/lanspeed/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/lanspeed
	$(INSTALL_DATA) \
		./htdocs/luci-static/resources/lanspeed/configForm.js \
		./htdocs/luci-static/resources/lanspeed/configStyle.js \
		./htdocs/luci-static/resources/lanspeed/configStyleArgon.js \
		./htdocs/luci-static/resources/lanspeed/configStyleAurora.js \
		./htdocs/luci-static/resources/lanspeed/configStyleBase.js \
		./htdocs/luci-static/resources/lanspeed/configStyleBootstrap.js \
		./htdocs/luci-static/resources/lanspeed/configStyleResponsive.js \
		./htdocs/luci-static/resources/lanspeed/configStyleShared.js \
		./htdocs/luci-static/resources/lanspeed/clientConnectionsLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailShellLive6.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleLive6.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleBaseLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleBootstrapLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleArgonLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleAuroraLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailStyleResponsiveLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailRefreshLive4.js \
		./htdocs/luci-static/resources/lanspeed/clientDetailViewLive6.js \
		./htdocs/luci-static/resources/lanspeed/format.js \
		./htdocs/luci-static/resources/lanspeed/ifaceConfig.js \
		./htdocs/luci-static/resources/lanspeed/rpc.js \
		./htdocs/luci-static/resources/lanspeed/rpcLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusCollector.js \
		./htdocs/luci-static/resources/lanspeed/statusIpLive4.js \
		./htdocs/luci-static/resources/lanspeed/statusRefreshLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusShellLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleArgonLive5.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleAuroraLive5.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleBaseLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleBootstrapLive5.js \
		./htdocs/luci-static/resources/lanspeed/statusStyleResponsiveLive5.js \
		./htdocs/luci-static/resources/lanspeed/statusOverviewLive6.js \
		./htdocs/luci-static/resources/lanspeed/statusViewLive6.js \
		./htdocs/luci-static/resources/lanspeed/theme.js \
		./htdocs/luci-static/resources/lanspeed/vocabLive5.js \
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
