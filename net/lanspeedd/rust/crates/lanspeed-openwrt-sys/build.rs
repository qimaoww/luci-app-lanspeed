use std::env;
use std::path::{Path, PathBuf};

const PLATFORM_LIBRARIES: [&str; 4] = ["ubus", "ubox", "blobmsg_json", "uci"];
const LINKER: &str = "x86_64-openwrt-linux-musl-gcc";

fn main() {
    println!("cargo:rerun-if-env-changed=OPENWRT_STAGING_LIB");
    println!("cargo:rerun-if-env-changed=STAGING_DIR");
    println!("cargo:rerun-if-env-changed=PATH");

    let library_dir = discover_library_dir().unwrap_or_else(|error| panic!("{error}"));
    println!("cargo::metadata=libdir={}", library_dir.display());
    println!("cargo:rustc-link-search=native={}", library_dir.display());
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath-link,{}",
        library_dir.display()
    );
    for library in PLATFORM_LIBRARIES {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
}

fn discover_library_dir() -> Result<PathBuf, String> {
    if let Some(directory) = env::var_os("OPENWRT_STAGING_LIB") {
        return validate_library_dir(PathBuf::from(directory), "OPENWRT_STAGING_LIB");
    }
    if let Some(staging_dir) = env::var_os("STAGING_DIR") {
        return validate_library_dir(
            PathBuf::from(staging_dir).join("usr/lib"),
            "STAGING_DIR/usr/lib",
        );
    }

    let linker = find_on_path(LINKER)?;
    let linker = linker
        .canonicalize()
        .map_err(|error| format!("failed to resolve {}: {error}", linker.display()))?;
    let toolchain_dir = linker
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("unexpected OpenWrt linker path: {}", linker.display()))?;
    let staging_dir = toolchain_dir.parent().ok_or_else(|| {
        format!(
            "OpenWrt linker is not below a staging_dir: {}",
            linker.display()
        )
    })?;
    validate_library_dir(
        staging_dir.join("target-x86_64_musl/usr/lib"),
        "SDK-relative target library directory",
    )
}

fn find_on_path(name: &str) -> Result<PathBuf, String> {
    let path = env::var_os("PATH").ok_or_else(|| "PATH is not set".to_owned())?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{name} was not found on PATH"))
}

fn validate_library_dir(directory: PathBuf, source: &str) -> Result<PathBuf, String> {
    let missing = PLATFORM_LIBRARIES
        .iter()
        .map(|library| format!("lib{library}.so"))
        .filter(|library| !directory.join(library).is_file())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(directory)
    } else {
        Err(format!(
            "{source} ({}) is missing: {}",
            directory.display(),
            missing.join(", ")
        ))
    }
}
