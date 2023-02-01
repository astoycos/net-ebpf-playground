use aya::programs::TracePoint;
use aya::{include_bytes_aligned, BpfLoader};
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
    // load pinned maps from /sys/fs/bpf/my-program
    .map_pin_path("/sys/fs/bpf")
    // finally load the code
    .load(include_bytes_aligned!("/home/astoycos/go/src/github.com/redhat-et/bpfd/examples/go-tracepoint-counter/bpf_bpfel.o"))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
    // load pinned maps from /sys/fs/bpf/my-program
    .map_pin_path("/sys/fs/bpf")
    // finally load the code
    .load(include_bytes_aligned!("/home/astoycos/go/src/github.com/redhat-et/bpfd/examples/go-tracepoint-counter/bpf_bpfel.o"))?;

    let program: &mut TracePoint = bpf.program_mut("tracepoint_kill_recorder").unwrap().try_into()?;
        
    program.load()?;
    program.attach("syscalls", "sys_enter_kill")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
