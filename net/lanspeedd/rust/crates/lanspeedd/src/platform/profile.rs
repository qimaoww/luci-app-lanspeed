#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformProfile {
    TcBpf,
    #[cfg(feature = "nss-platform")]
    NssAarch64,
}

#[cfg(feature = "nss-platform")]
pub const COMPILED_PROFILE: PlatformProfile = PlatformProfile::NssAarch64;
#[cfg(not(feature = "nss-platform"))]
pub const COMPILED_PROFILE: PlatformProfile = PlatformProfile::TcBpf;

impl PlatformProfile {
    pub const fn uses_nss(self) -> bool {
        match self {
            Self::TcBpf => false,
            #[cfg(feature = "nss-platform")]
            Self::NssAarch64 => true,
        }
    }

    pub const fn uses_access_edge(self) -> bool {
        self.uses_nss()
    }
}
