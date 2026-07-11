use std::{env, error::Error, io};

use aya::{
    maps::HashMap,
    programs::{
        tc::{self, NlOptions, TcAttachOptions, TcHandle},
        SchedClassifier, TcAttachType, TcError,
    },
    Ebpf,
};
use lanspeed_common::{BYTE_COUNTS_MAP, BYTE_COUNT_KEY};

const TC_PRIORITY: u16 = 49152;
const TC_HANDLE: TcHandle = TcHandle::new(0, 0x1eed);

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let object = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: lanspeedd <ebpf-object> [interface]",
        )
    })?;
    let interface = args.next();
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many arguments").into());
    }

    let mut ebpf = Ebpf::load_file(object)?;
    let Some(interface) = interface else {
        println!("loaded eBPF object successfully");
        return Ok(());
    };
    let interface = interface
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface is not UTF-8"))?;

    match tc::qdisc_add_clsact(&interface) {
        Ok(()) | Err(TcError::AlreadyAttached) => {}
        Err(error) => return Err(error.into()),
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut("lanspeed_count")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lanspeed_count program missing"))?
        .try_into()?;
    program.load()?;
    let options = TcAttachOptions::Netlink(NlOptions {
        priority: TC_PRIORITY,
        handle: TC_HANDLE,
        classid: None,
    });
    let link_id = program.attach_with_options(&interface, TcAttachType::Ingress, options)?;

    let read_result = (|| -> Result<u64, Box<dyn Error>> {
        let map = ebpf
            .map(BYTE_COUNTS_MAP)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "BYTE_COUNTS map missing"))?;
        let counters = HashMap::<_, u32, u64>::try_from(map)?;
        Ok(counters.get(&BYTE_COUNT_KEY, 0).unwrap_or(0))
    })();

    let program: &mut SchedClassifier = ebpf
        .program_mut("lanspeed_count")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lanspeed_count program missing"))?
        .try_into()?;
    let detach_result = program.detach(link_id);
    detach_result?;

    println!("counted {} bytes", read_result?);
    Ok(())
}
