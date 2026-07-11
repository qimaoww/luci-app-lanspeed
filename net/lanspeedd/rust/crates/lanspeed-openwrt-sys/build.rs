use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=OPENWRT_STAGING_LIB");
    if let Some(directory) = env::var_os("OPENWRT_STAGING_LIB") {
        println!(
            "cargo:rustc-link-search=native={}",
            directory.to_string_lossy()
        );
    }
    for library in ["ubus", "ubox", "blobmsg_json", "uci"] {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
}
