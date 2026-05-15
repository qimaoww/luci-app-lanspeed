include $(TOPDIR)/rules.mk

PKG_NAME:=lanspeedd
PKG_VERSION:=0.1.1
PKG_RELEASE:=6

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=
PKG_BUILD_DEPENDS:=bpf-headers

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/lanspeedd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=LAN speed monitor daemon
  DEPENDS:=+libubox +libubus +libuci +libblobmsg-json +libjson-c +libbpf +libmnl +kmod-nf-conntrack-netlink +tc-tiny
endef

define Package/lanspeedd/description
 Base daemon skeleton for LAN client speed monitoring.
endef

define Package/lanspeedd-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Optional BPF assets for lanspeedd
  DEPENDS:=+lanspeedd +libbpf $(BPF_DEPENDS)
endef

define Package/lanspeedd-bpf/description
 Optional BPF model/artifacts for Full mode support. The base daemon runs
 without this package and degrades when runtime BPF assets are absent.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/Makefile ./src/*.c ./src/*.h ./src/*.json $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall -Wextra -DLANSPEED_RELEASE=\\\"$(PKG_RELEASE)\\\"" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LIBS="-lubox -lubus -luci -lblobmsg_json -ljson-c -lbpf -lmnl"
	$(if $(CONFIG_PACKAGE_lanspeedd-bpf),$(call CompileBPF,$(PKG_BUILD_DIR)/lanspeed_tc.bpf.c),:)
	$(if $(CONFIG_PACKAGE_lanspeedd-bpf),$(CP) $(PKG_BUILD_DIR)/lanspeed_tc.bpf.o $(PKG_BUILD_DIR)/lanspeed_tc.o,:)
endef

define Package/lanspeedd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lanspeedd $(1)/usr/sbin/lanspeedd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/lanspeedd $(1)/etc/init.d/lanspeedd
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/90-lanspeedd $(1)/etc/hotplug.d/iface/90-lanspeedd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/lanspeed $(1)/etc/config/lanspeed
	$(INSTALL_DIR) $(1)/usr/share/lanspeed
	$(INSTALL_DATA) ./files/usr/share/lanspeed/schema.json $(1)/usr/share/lanspeed/schema.json
endef

define Package/lanspeedd-bpf/install
	$(INSTALL_DIR) $(1)/usr/share/lanspeed/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/collector-model.json $(1)/usr/share/lanspeed/bpf/collector-model.json
	$(INSTALL_DIR) $(1)/usr/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lanspeed_tc.o $(1)/usr/lib/bpf/lanspeed_tc.o
endef

$(eval $(call BuildPackage,lanspeedd))
$(eval $(call BuildPackage,lanspeedd-bpf))
