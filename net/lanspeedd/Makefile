include $(TOPDIR)/rules.mk

PKG_NAME:=lanspeedd
PKG_VERSION:=1.2.0
PKG_RELEASE:=2

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1
RUST_PKG_LOCKED:=1

LANSPEED_BUILD_BPF ?= $(if $(CONFIG_PACKAGE_lanspeedd-bpf),1,0)
LANSPEED_BPF_ENABLED:=$(filter 1,$(LANSPEED_BUILD_BPF))
LANSPEED_NSS_ECM_BPF_ENABLED:=$(filter aarch64,$(ARCH))
LANSPEED_X86_CONTROL_DEPENDS:=+TARGET_x86:tc-full +TARGET_x86:ip +TARGET_x86:nftables +TARGET_x86:conntrack +TARGET_x86:kmod-ifb +TARGET_x86:kmod-sched-core +TARGET_x86:kmod-sched
LANSPEED_NSS_CONTROL_DEPENDS:=+TARGET_qualcommax:tc-full +TARGET_qualcommax:ip +TARGET_qualcommax:nftables +TARGET_qualcommax:conntrack +TARGET_qualcommax:kmod-ifb +TARGET_qualcommax:kmod-sched-core +TARGET_qualcommax:kmod-qca-nss-drv-igs +TARGET_qualcommax:kmod-lanspeed-nss-control
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)$(if $(LANSPEED_BPF_ENABLED),-bpf,)

BPF_LINKER_ARCHIVE:=bpf-linker-0.10.3-x86_64-unknown-linux-musl.tar.gz
BPF_LINKER_DIR:=$(PKG_BUILD_DIR)/host-tools/bin
BPF_LINKER:=$(BPF_LINKER_DIR)/bpf-linker

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Download/bpf-linker
  FILE:=bpf-linker-0.10.3-x86_64-unknown-linux-musl.tar.gz
  URL:=https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/
  URL_FILE:=bpf-linker-x86_64-unknown-linux-musl.tar.gz
  HASH:=0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c
endef

ifneq ($(LANSPEED_BPF_ENABLED),)
ifeq ($(HOST_ARCH),x86_64)
$(eval $(call Download,bpf-linker))
endif
endif

define Package/lanspeedd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=LAN speed monitor daemon
  SOURCE:=lanspeedd
  DEPENDS:=@(aarch64||x86_64) +libgcc +kmod-nf-conntrack-netlink $(LANSPEED_X86_CONTROL_DEPENDS) $(LANSPEED_NSS_CONTROL_DEPENDS)
endef

define Package/lanspeedd/description
 Rust/Aya daemon for LAN client speed monitoring.
endef

define Package/lanspeedd/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT:-}" ] && exit 0
umask 077
token_file=/var/run/lanspeedd.postinst-restart
token="$$$$.$$(date +%s)"
printf '%s\n' "$${token}" > "$${token_file}" || exit 0
(
	sleep 2
	[ "$$(cat "$${token_file}" 2>/dev/null)" = "$${token}" ] || exit 0
	rm -f "$${token_file}"
	/etc/init.d/lanspeedd restart >/dev/null 2>&1 || true
) &
exit 0
endef

define Package/lanspeedd-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=BPF assets for lanspeedd
  SOURCE:=lanspeedd
  DEPENDS:=@!BIG_ENDIAN +lanspeedd +tc-full +kmod-sched-bpf
endef

define Package/lanspeedd-bpf/description
 Required Aya eBPF programs for luci-app-lanspeed Full mode support.
 The package installs architecture-matched kfunc and fallback TC-BPF objects.
 On aarch64 it additionally installs the isolated NSS ECM kprobe object.
endef

define Package/lanspeedd-bpf/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT:-}" ] && exit 0
umask 077
token_file=/var/run/lanspeedd.postinst-restart
token="$$$$.$$(date +%s)"
printf '%s\n' "$${token}" > "$${token_file}" || exit 0
(
	sleep 2
	[ "$$(cat "$${token_file}" 2>/dev/null)" = "$${token}" ] || exit 0
	rm -f "$${token_file}"
	/etc/init.d/lanspeedd restart >/dev/null 2>&1 || true
) &
exit 0
endef

define Build/Prepare
	$(if $(LANSPEED_BPF_ENABLED),test "$(HOST_ARCH)" = "x86_64" || { echo "lanspeedd-bpf requires an x86_64 build host for the pinned bpf-linker binary" >&2; exit 1; },:)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./rust/Cargo.toml ./rust/Cargo.lock $(PKG_BUILD_DIR)/
	$(CP) ./rust/.cargo $(PKG_BUILD_DIR)/
	$(CP) ./rust/crates $(PKG_BUILD_DIR)/
	$(CP) ./rust/vendor $(PKG_BUILD_DIR)/
	$(CP) ./src/collector-model.json $(PKG_BUILD_DIR)/
	$(if $(LANSPEED_BPF_ENABLED),mkdir -p $(BPF_LINKER_DIR),:)
	$(if $(LANSPEED_BPF_ENABLED),$(TAR) -C $(BPF_LINKER_DIR) -xzf $(DL_DIR)/$(BPF_LINKER_ARCHIVE),:)
endef

define Build/Compile
	+cd $(PKG_BUILD_DIR) && \
		$(CARGO_HOST_CONFIG_VARS) \
		CARGO_BUILD_TARGET="$(RUSTC_HOST_ARCH)" \
		cargo build -v --manifest-path Cargo.toml -p lanspeed-build --release --target $(RUSTC_HOST_ARCH) --locked --offline
	+$(CARGO_PKG_VARS) \
		LANSPEED_USERSPACE_TARGET="$(RUSTC_TARGET_ARCH)" \
		LANSPEED_VERSION="$(PKG_VERSION)" \
		LANSPEED_RELEASE="$(PKG_RELEASE)" \
		$(PKG_BUILD_DIR)/target/$(RUSTC_HOST_ARCH)/release/lanspeed-build build-userspace
ifneq ($(LANSPEED_BPF_ENABLED),)
	+$(CARGO_HOST_CONFIG_VARS) \
			MAKEFLAGS="$(PKG_JOBS)" \
			CARGO_PROFILE_RELEASE_PANIC=abort \
			BPF_LINKER="$(BPF_LINKER)" \
			LANSPEED_BPF_TARGET_ARCH="$(ARCH)" \
			$(PKG_BUILD_DIR)/target/$(RUSTC_HOST_ARCH)/release/lanspeed-build build-ebpf
endif
endef

define Package/lanspeedd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/lanspeedd $(1)/usr/sbin/lanspeedd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/lanspeedd $(1)/etc/init.d/lanspeedd
	if [ "$(CONFIG_TARGET_qualcommax)" = "y" ]; then \
		$(SED) '/procd_set_param respawn/a\	procd_set_param term_timeout 15' $(1)/etc/init.d/lanspeedd; \
	fi
	if [ "$(CONFIG_TARGET_qualcommax)" != "y" ]; then \
		$(INSTALL_DIR) $(1)/etc/hotplug.d/iface; \
		$(INSTALL_BIN) ./files/etc/hotplug.d/iface/90-lanspeedd $(1)/etc/hotplug.d/iface/90-lanspeedd; \
	fi
	$(INSTALL_DIR) $(1)/etc/config
	if [ "$(ARCH)" = "x86_64" ]; then \
		$(INSTALL_CONF) ./files/etc/config/lanspeed.x86 $(1)/etc/config/lanspeed; \
	else \
		$(INSTALL_CONF) ./files/etc/config/lanspeed $(1)/etc/config/lanspeed; \
	fi
	if [ "$(ARCH)" = "x86_64" ]; then \
		$(INSTALL_DIR) $(1)/etc/uci-defaults; \
		$(INSTALL_BIN) ./files/etc/uci-defaults/95-lanspeed-x86-profile $(1)/etc/uci-defaults/95-lanspeed-x86-profile; \
	fi
	if [ "$(CONFIG_TARGET_qualcommax)" = "y" ]; then \
		$(INSTALL_DIR) $(1)/etc/uci-defaults; \
		$(INSTALL_BIN) ./files/etc/uci-defaults/94-lanspeed-nss-shaping $(1)/etc/uci-defaults/94-lanspeed-nss-shaping; \
	fi
	$(INSTALL_DIR) $(1)/usr/share/lanspeed
	$(INSTALL_DATA) ./files/usr/share/lanspeed/schema.json $(1)/usr/share/lanspeed/schema.json
endef

define Package/lanspeedd-bpf/install
	$(INSTALL_DIR) $(1)/usr/share/lanspeed/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/collector-model.json $(1)/usr/share/lanspeed/bpf/collector-model.json
	$(INSTALL_DIR) $(1)/usr/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/lanspeed-ebpf-kfunc $(1)/usr/lib/bpf/lanspeed-ebpf-kfunc.o
	$(LN) lanspeed-ebpf-kfunc.o $(1)/usr/lib/bpf/lanspeed-ebpf-kfunc
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/lanspeed-ebpf-fallback $(1)/usr/lib/bpf/lanspeed-ebpf-fallback.o
		$(LN) lanspeed-ebpf-fallback.o $(1)/usr/lib/bpf/lanspeed-ebpf-fallback
		if [ -n "$(LANSPEED_NSS_ECM_BPF_ENABLED)" ]; then \
			$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/lanspeed-ebpf-ecm $(1)/usr/lib/bpf/lanspeed-ebpf-ecm.o; \
			$(LN) lanspeed-ebpf-ecm.o $(1)/usr/lib/bpf/lanspeed-ebpf-ecm; \
		fi
endef

$(eval $(call BuildPackage,lanspeedd))
$(eval $(call BuildPackage,lanspeedd-bpf))
