use aya::{include_bytes_aligned, Bpf};
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya_log::BpfLogger;
use std::net::Ipv4Addr;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use tc_udp_redirect_common::{VipKey, Backend};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc-udp-redirect"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc-udp-redirect"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc_udp_redirect").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    //program.attach(&opt.iface, TcAttachType::Egress)?;

    let mut backends: HashMap<_,VipKey,Backend> = 
        HashMap::try_from(bpf.map_mut("BACKENDS")?)?;
    
    let vip_addr: u32 = Ipv4Addr::new(10, 8, 125, 12).try_into()?;

    let key = VipKey{
        vip: vip_addr,
        port: 9875,
    };


    let backend = Backend{
        daddr: Ipv4Addr::new(192, 168, 10, 5).try_into()?,
        dport: 9875,
        ifindex: 8,
    };

    backends.insert(key, backend, 0)?;
    info!("Inserted Backend {:#?} with key {:#?}", backend, key);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
