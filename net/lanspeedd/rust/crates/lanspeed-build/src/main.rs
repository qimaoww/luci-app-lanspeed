use std::{env, error::Error};

use lanspeed_build::{build, BuildError, BuildTarget};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or(BuildError::Usage)?;
    if args.next().is_some() {
        return Err(BuildError::Usage.into());
    }

    build(BuildTarget::parse(&command)?)?;
    Ok(())
}
