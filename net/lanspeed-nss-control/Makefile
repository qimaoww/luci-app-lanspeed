include $(TOPDIR)/rules.mk

PKG_NAME:=lanspeed-nss-control
PKG_VERSION:=1.2.0
PKG_RELEASE:=2
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/lanspeed-nss-control
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Support
  TITLE:=LAN Speed staged NSS ingress-shaper control
  SOURCE:=lanspeed-nss-control
  DEPENDS:=@TARGET_qualcommax +kmod-ifb +kmod-qca-nss-drv +kmod-qca-nss-drv-igs
  FILES:=$(PKG_BUILD_DIR)/lanspeed_nss_control.ko
endef

define KernelPackage/lanspeed-nss-control/description
 Stages a QCA NSS IGS node on a LAN Speed-owned IFB before userspace
 transactionally publishes the corresponding physical-edge nexthop.
endef

define Package/kmod-lanspeed-nss-control/postinst
#!/bin/sh
chown 0:0 \
	"$${IPKG_INSTROOT}/lib/apk/packages/kmod-lanspeed-nss-control.list" \
	"$${IPKG_INSTROOT}/lib/modules/$(LINUX_VERSION)/lanspeed_nss_control.ko"
chmod 0644 \
	"$${IPKG_INSTROOT}/lib/apk/packages/kmod-lanspeed-nss-control.list" \
	"$${IPKG_INSTROOT}/lib/modules/$(LINUX_VERSION)/lanspeed_nss_control.ko"
endef

EXTRA_CFLAGS:= \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv

MAKE_OPTS:= \
	$(KERNEL_MAKE_FLAGS) \
	M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,lanspeed-nss-control))
