use std::{env, error::Error, fs, io, os::fd::OwnedFd, thread, time::Duration};

use aya::{
    maps::HashMap,
    programs::{
        tc::{self, NlOptions, TcAttachOptions, TcHandle},
        SchedClassifier, TcAttachType, TcError,
    },
    Ebpf, EbpfLoader, Pod,
};
use lanspeed_common::{
    LanspeedCounters, LanspeedKey, CLIENTS_MAP_NAME, EGRESS_EARLY_PROGRAM_NAME,
    EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME, INGRESS_PROGRAM_NAME,
};
use lanspeedd::{
    is_known_kfunc_metadata_incompatibility, load_with_fallback, patch_conntrack_kfunc_calls,
};

const TC_PRIORITY: u16 = 49152;
const TC_HANDLE: TcHandle = TcHandle::new(0, 0x1eed);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ClientKey(LanspeedKey);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ClientCounters(LanspeedCounters);

unsafe impl Pod for ClientKey {}
unsafe impl Pod for ClientCounters {}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let kfunc_object = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: lanspeedd <kfunc-object> <fallback-object> [interface [seconds]]",
        )
    })?;
    let fallback_object = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: lanspeedd <kfunc-object> <fallback-object> [interface [seconds]]",
        )
    })?;
    let interface = args.next();
    let seconds = args
        .next()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seconds is not UTF-8"))?
                .parse::<u64>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })
        .transpose()?
        .unwrap_or(3);
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many arguments").into());
    }

    let mut object = fs::read(kfunc_object)?;
    let loaded = load_with_fallback(
        || {
            let module_btf_fds = patch_conntrack_kfunc_calls(&mut object)?;
            load_program_object(&object, module_btf_fds)
        },
        || {
            let fallback = fs::read(fallback_object)?;
            load_program_object(&fallback, Vec::new())
        },
        is_known_kernel_incompatibility,
    )?;
    if let Some(error) = loaded.primary_error {
        eprintln!(
            "warning: local nf_conntrack kfunc metadata is incompatible; \
             loading byte/packet accounting fallback: {error}"
        );
    }
    let mut ebpf = loaded.value;
    let Some(interface) = interface else {
        println!("loaded production eBPF object successfully");
        return Ok(());
    };
    let interface = interface
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface is not UTF-8"))?;

    match tc::qdisc_add_clsact(&interface) {
        Ok(()) | Err(TcError::AlreadyAttached) => {}
        Err(error) => return Err(error.into()),
    }

    let options = || {
        TcAttachOptions::Netlink(NlOptions {
            priority: TC_PRIORITY,
            handle: TC_HANDLE,
            classid: None,
        })
    };
    let ingress_link = classifier(&mut ebpf, INGRESS_PROGRAM_NAME)?.attach_with_options(
        &interface,
        TcAttachType::Ingress,
        options(),
    )?;
    let egress_link = match classifier(&mut ebpf, EGRESS_PROGRAM_NAME)?.attach_with_options(
        &interface,
        TcAttachType::Egress,
        options(),
    ) {
        Ok(link) => link,
        Err(error) => {
            classifier(&mut ebpf, INGRESS_PROGRAM_NAME)?.detach(ingress_link)?;
            return Err(error.into());
        }
    };

    thread::sleep(Duration::from_secs(seconds));
    let read_result = read_clients(&mut ebpf);
    let egress_detach = classifier(&mut ebpf, EGRESS_PROGRAM_NAME)?.detach(egress_link);
    let ingress_detach = classifier(&mut ebpf, INGRESS_PROGRAM_NAME)?.detach(ingress_link);
    egress_detach?;
    ingress_detach?;

    for (key, counters) in read_result? {
        println!(
            "ifindex={} vlan={} direction={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} bytes={} packets={} tcp={} udp={}",
            key.ifindex,
            key.vlan_or_zone,
            key.direction,
            key.mac[0], key.mac[1], key.mac[2], key.mac[3], key.mac[4], key.mac[5],
            counters.bytes,
            counters.packets,
            counters.tcp_conns,
            counters.udp_conns,
        );
    }
    Ok(())
}

fn load_programs(ebpf: &mut Ebpf) -> Result<(), aya::programs::ProgramError> {
    for name in [
        INGRESS_PROGRAM_NAME,
        EGRESS_PROGRAM_NAME,
        INGRESS_EARLY_PROGRAM_NAME,
        EGRESS_EARLY_PROGRAM_NAME,
    ] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(aya::programs::ProgramError::UnexpectedProgramType)?
            .try_into()?;
        program.load()?;
    }
    Ok(())
}

fn load_program_object(bytes: &[u8], module_btf_fds: Vec<OwnedFd>) -> Result<Ebpf, Box<dyn Error>> {
    let mut loader = EbpfLoader::new();
    loader.kfunc_btf_fds(module_btf_fds);
    let mut ebpf = loader.load(bytes)?;
    load_programs(&mut ebpf)?;
    Ok(ebpf)
}

fn is_known_kernel_incompatibility(error: &Box<dyn Error>) -> bool {
    if let Some(error) = error.downcast_ref::<lanspeedd::KfuncPatchError>() {
        return error.is_kernel_incompatibility();
    }
    match error.downcast_ref::<aya::programs::ProgramError>() {
        Some(aya::programs::ProgramError::LoadError { verifier_log, .. }) => {
            is_known_kfunc_metadata_incompatibility(&verifier_log.to_string())
        }
        _ => false,
    }
}

fn classifier<'a>(
    ebpf: &'a mut Ebpf,
    name: &str,
) -> Result<&'a mut SchedClassifier, Box<dyn Error>> {
    Ok(ebpf
        .program_mut(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} missing")))?
        .try_into()?)
}

fn read_clients(ebpf: &mut Ebpf) -> Result<Vec<(LanspeedKey, LanspeedCounters)>, Box<dyn Error>> {
    let map = ebpf
        .map(CLIENTS_MAP_NAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lanspeed_clients map missing"))?;
    let clients = HashMap::<_, ClientKey, ClientCounters>::try_from(map)?;
    clients
        .iter()
        .map(|entry| {
            entry
                .map(|(key, counters)| (key.0, counters.0))
                .map_err(Into::into)
        })
        .collect()
}
