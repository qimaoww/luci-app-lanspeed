use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_OPENWRT");
    println!("cargo:rerun-if-env-changed=DEP_LANSPEED_OPENWRT_SYS_LIBDIR");

    if env::var_os("CARGO_FEATURE_OPENWRT").is_none() {
        return;
    }

    let library_dir = env::var("DEP_LANSPEED_OPENWRT_SYS_LIBDIR")
        .expect("lanspeed-openwrt-sys did not export its SDK library directory");
    println!("cargo:rustc-link-arg=-Wl,-rpath-link,{library_dir}");
}
