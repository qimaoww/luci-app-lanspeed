use std::error::Error;

#[cfg(feature = "openwrt")]
fn main() -> Result<(), Box<dyn Error>> {
    lanspeedd::production::run().map_err(Into::into)
}

#[cfg(not(feature = "openwrt"))]
fn main() -> Result<(), Box<dyn Error>> {
    Err("lanspeedd production binary requires the openwrt feature".into())
}
