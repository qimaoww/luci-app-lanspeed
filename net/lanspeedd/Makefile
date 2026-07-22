include $(TOPDIR)/rules.mk

PKG_NAME:=lanspeedd
PKG_VERSION:=1.1.2
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1
RUST_PKG_LOCKED:=1

LANSPEED_BUILD_BPF ?= $(if $(CONFIG_PACKAGE_lanspeedd-bpf),1,0)
LANSPEED_BPF_ENABLED:=$(filter 1,$(LANSPEED_BUILD_BPF))
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
  DEPENDS:=@(aarch64||x86_64) +libubox +libubus +libuci +libblobmsg-json +kmod-nf-conntrack-netlink
endef

define Package/lanspeedd/description
 Rust/Aya daemon for LAN client speed monitoring.
endef

define Package/lanspeedd-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=BPF assets for lanspeedd
  DEPENDS:=@!BIG_ENDIAN +lanspeedd +tc-tiny +kmod-sched-bpf
endef

define Package/lanspeedd-bpf/description
 Required Aya eBPF programs for luci-app-lanspeed Full mode support.
 The package installs the kfunc and fallback tc/eBPF runtime objects.
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
		OPENWRT_STAGING_LIB="$(STAGING_DIR)/usr/lib" \
		$(PKG_BUILD_DIR)/target/$(RUSTC_HOST_ARCH)/release/lanspeed-build build-userspace
ifneq ($(LANSPEED_BPF_ENABLED),)
	+$(CARGO_HOST_CONFIG_VARS) \
		MAKEFLAGS="$(PKG_JOBS)" \
		CARGO_PROFILE_RELEASE_PANIC=abort \
		BPF_LINKER="$(BPF_LINKER)" \
		$(PKG_BUILD_DIR)/target/$(RUSTC_HOST_ARCH)/release/lanspeed-build build-ebpf
endif
endef

define Package/lanspeedd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/release/lanspeedd $(1)/usr/sbin/lanspeedd
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
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/lanspeed-ebpf-kfunc $(1)/usr/lib/bpf/lanspeed-ebpf-kfunc.o
	$(LN) lanspeed-ebpf-kfunc.o $(1)/usr/lib/bpf/lanspeed-ebpf-kfunc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/lanspeed-ebpf-fallback $(1)/usr/lib/bpf/lanspeed-ebpf-fallback.o
	$(LN) lanspeed-ebpf-fallback.o $(1)/usr/lib/bpf/lanspeed-ebpf-fallback
endef

$(eval $(call BuildPackage,lanspeedd))
$(eval $(call BuildPackage,lanspeedd-bpf))
