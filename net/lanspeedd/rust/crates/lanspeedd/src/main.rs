use std::{env, error::Error, io, thread, time::Duration};

use lanspeedd::collectors::bpf::runtime::{AttachMode, AyaAdapter, BpfRuntime, SystemAyaAdapter};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let kfunc_object = args.next().ok_or_else(usage)?;
    let fallback_object = args.next().ok_or_else(usage)?;
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

    let mut adapter = SystemAyaAdapter::new();
    let mut runtime = BpfRuntime::load(&mut adapter, kfunc_object, fallback_object)?;
    if let Some(error) = runtime.primary_kfunc_incompatibility() {
        eprintln!(
            "warning: local kernel does not expose compatible nf_conntrack kfunc metadata; \
             loading byte/packet accounting fallback: {error}"
        );
    }
    let Some(interface) = interface else {
        println!("loaded production eBPF object successfully");
        return Ok(());
    };
    let interface = interface
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface is not UTF-8"))?;
    runtime.attach_interface(&mut adapter, &interface, AttachMode::Normal)?;

    thread::sleep(Duration::from_secs(seconds));
    let read_result = adapter.read_clients();
    let shutdown_result = runtime.shutdown(&mut adapter);
    shutdown_result?;

    for sample in read_result?.entries {
        let key = sample.key;
        let counters = sample.counters;
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

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: lanspeedd <kfunc-object> <fallback-object> [interface [seconds]]",
    )
}
