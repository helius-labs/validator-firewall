mod ip_service;
mod stats_service;

use crate::ip_service::GossipWatcher;
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use serde::Deserialize;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::signal;

#[derive(Debug, Parser)]
struct HVFConfig {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long)]
    static_overrides: Option<PathBuf>,
    #[clap(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_endpoint: String,
    #[arg(short, long, value_name = "PORT", value_parser = clap::value_parser!(u16), num_args = 1..)]
    protected_ports: Vec<u16>,
}

#[derive(Deserialize, Debug)]
struct NameAddressPair {
    name: String,
    ip: Ipv4Addr,
}

#[derive(Deserialize, Debug)]
struct StaticOverrides {
    nodes: Vec<NameAddressPair>,
}

const ALLOW_LIST_MAP: &str = "hvf_allow_list";
const PROTECTED_PORTS_MAP: &str = "hvf_protected_ports";
const ALL_TRAFFIC_MAP: &str = "hvf_all_ip_stats";
const BLOCKED_TRAFFIC_MAP: &str = "hvf_blocked_ip_stats";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = HVFConfig::parse();

    env_logger::init();
    let static_overrides = {
        let mut local_overrides = HashSet::new();
        if let Some(path) = config.static_overrides {
            let overrides = load_static_overrides(path)?;
            for node in overrides.nodes.iter() {
                local_overrides.insert(u32::from(node.ip));
            }
            info!("Loaded static overrides: {:?}", overrides);
        };
        Arc::new(local_overrides)
    };

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/validator-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/validator-firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("validator_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&config.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Filtering UDP ports: {:?}", config.protected_ports);
    push_ports_to_map(&mut bpf, config.protected_ports)?;

    let exit = Arc::new(AtomicBool::new(false));
    let gossip_exit = exit.clone();

    let gossip_watcher = GossipWatcher::new(
        gossip_exit,
        Arc::new(RpcClient::new(config.rpc_endpoint.clone())),
        static_overrides.clone(),
    );

    //Update the allow_list in the background
    let map = bpf.take_map(ALLOW_LIST_MAP).unwrap();
    let gossip_handle = tokio::spawn(async move {
        gossip_watcher.run(map).await;
    });

    //Start the stats service
    let stats_exit = exit.clone();
    let stats_service = stats_service::StatsService::new(
        stats_exit,
        10,
        bpf.take_map(ALL_TRAFFIC_MAP).unwrap(),
        bpf.take_map(BLOCKED_TRAFFIC_MAP).unwrap(),
    );
    let stats_handle = tokio::spawn(async move {
        stats_service.run().await;
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    exit.store(true, std::sync::atomic::Ordering::SeqCst);
    gossip_handle.await?;
    stats_handle.await?;
    info!("Exiting...");

    Ok(())
}

fn load_static_overrides(path: PathBuf) -> Result<StaticOverrides, anyhow::Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let overrides = serde_yaml::from_reader(reader)?;
    Ok(overrides)
}

fn push_ports_to_map(bpf: &mut Bpf, ports: Vec<u16>) -> Result<(), anyhow::Error> {
    let mut protected_ports: HashMap<_, u16, u8> =
        HashMap::try_from(bpf.map_mut(PROTECTED_PORTS_MAP).unwrap()).unwrap();
    for port in ports {
        protected_ports.insert(&port, &0, 0)?;
    }
    Ok(())
}
