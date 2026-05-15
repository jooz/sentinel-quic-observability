use std::net::Ipv4Addr;
use aya::include_bytes_aligned;
use aya::programs::Tc;
use aya::Ebpf;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod quic_parser;
mod reporting;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();

    #[cfg(debug_assertions)]
    let bpf_data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/sentinel-ebpf");
    #[cfg(not(debug_assertions))]
    let bpf_data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/sentinel-ebpf");

    let mut ebpf = Ebpf::load(bpf_data)?;
    
    let program: &mut Tc = ebpf.program_mut("sentinel_tc").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, aya::programs::TcAttachType::Ingress)?;

    info!("Sentinel Agent started on interface {}. Capturing QUIC/TLS SNI...", args.iface);

    reporting::start_report_loop(&mut ebpf).await?;

    Ok(())
}
