mod ip_service;
mod stats_service;

mod config;
mod leader_tracker;

use crate::config::{load_static_overrides, NameAddressPair};
use crate::ip_service::{ DenyListService, DenyListStateUpdater, HttpDenyListClient, DuckDbDenyListClient, NoOpDenyListClient};
use crate::leader_tracker::{CommandControlService, RPCLeaderTracker};
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use cidr::Ipv4Cidr;
use clap::Parser;
use log::{debug, error, info, warn};
use serde::Deserialize;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
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
    #[clap(short, long, default_value = "http://localhost:8899")]
    rpc_endpoint: String,
    #[arg(short, long, value_name = "PORT", value_parser = clap::value_parser!(u16), num_args = 0..)]
    protected_ports: Vec<u16>,
    #[clap(short, long)]
    leader_id: Option<String>,
    #[clap(short, long)]
    external_ip_service_url: Option<String>,
    #[clap(short, long)]
    query_file: Option<PathBuf>,
}

const DENY_LIST_MAP: &str = "hvf_deny_list";
const DENY_LIST_LPM: &str = "hvf_deny_lpm";
const PROTECTED_PORTS_MAP: &str = "hvf_protected_ports";
const CONNECTION_STATS: &str = "hvf_stats";
const CNC_ARRAY: &str = "hvf_cnc";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = HVFConfig::parse();

    tracing_subscriber::fmt().json().init();

    let static_overrides = {
        let mut local_allow = HashSet::new();
        let mut local_deny = HashSet::new();

        // Load static overrides if provided
        if let Some(path) = config.static_overrides {
            let overrides = load_static_overrides(path)?;
            let denied: HashSet<Ipv4Cidr> = overrides.deny.iter().map(|x| x.ip.clone()).collect();
            let intersection: Vec<&NameAddressPair> = overrides
                .allow
                .iter()
                .filter(|x| denied.contains(&x.ip))
                .collect();

            if !intersection.is_empty() {
                error!(
                    "Static overrides contain overlapping entries for deny and allow: {:?}",
                    intersection
                );
                std::process::exit(1);
            }
            for node in overrides.allow.iter() {
                local_allow.insert(node.ip);
            }
            for node in overrides.deny.iter() {
                local_deny.insert(node.ip);
            }

            info!("Loaded static overrides: {:?}", overrides);
        };
        Arc::new((local_allow, local_deny))
    };

    let protected_ports = if config.protected_ports.is_empty() {
        warn!("No protected ports provided, defaulting to 8009 and 8010");
        vec![8009, 8010]
    } else {
        config.protected_ports.clone()
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

    info!("Filtering UDP ports: {:?}", protected_ports);
    push_ports_to_map(&mut bpf, protected_ports)?;

    let exit = Arc::new(AtomicBool::new(false));
    let gossip_exit = exit.clone();

    let ip_svc_handle = if let Some(url) = config.external_ip_service_url {
        info!("Using external IP service: {}", url);
        let ip_service = HttpDenyListClient::new(url);
        let state_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(ip_service)),
            static_overrides.clone(),
        );

        let map = bpf.take_map(DENY_LIST_MAP).unwrap();
        let lpm_map = bpf.take_map(DENY_LIST_LPM).unwrap();
        let state_updater_handle = tokio::spawn(async move {
            state_updater.run(map, lpm_map).await;
        });

        state_updater_handle
    } else if let Some(query_file) = config.query_file {
        //read contents of file to string
        let query = std::fs::read_to_string(query_file)?;

        let s_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(DuckDbDenyListClient::new(
                query,
            ))),
            static_overrides.clone(),
        );

        let map = bpf.take_map(DENY_LIST_MAP).unwrap();
        let lpm_map = bpf.take_map(DENY_LIST_LPM).unwrap();
        let gossip_handle = tokio::spawn(async move {
            s_updater.run(map, lpm_map).await;
        });
        gossip_handle
    } else {
        //Default to no-op deny list client

        warn!("No deny list client specified, only using static overrides");
        let noop = NoOpDenyListClient {};
        let s_updater = DenyListStateUpdater::new(
            gossip_exit,
            Arc::new(DenyListService::new(noop)),
            static_overrides.clone(),
        );

        let map = bpf.take_map(DENY_LIST_MAP).unwrap();
        let lpm_map = bpf.take_map(DENY_LIST_LPM).unwrap();
        let gossip_handle = tokio::spawn(async move {
            s_updater.run(map, lpm_map).await;
        });
        gossip_handle
    };

    //Start the leader tracker
    let tracker = Arc::new(RPCLeaderTracker::new(
        exit.clone(),
        RpcClient::new(config.rpc_endpoint.clone()),
        12,
        config.leader_id,
    ));
    let bg_tracker = tracker.clone();
    let tracker_handle = tokio::spawn(async move {
        bg_tracker.clone().run().await;
    });

    let mut tracker_service =
        CommandControlService::new(exit.clone(), tracker, bpf.take_map(CNC_ARRAY).unwrap());
    let tracker_service_handle = tokio::spawn(async move {
        tracker_service.run().await;
    });

    //Start the stats service
    let stats_exit = exit.clone();
    let stats_service =
        stats_service::StatsService::new(stats_exit, 10, bpf.take_map(CONNECTION_STATS).unwrap());
    let stats_handle = tokio::spawn(async move {
        stats_service.run().await;
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    exit.store(true, std::sync::atomic::Ordering::SeqCst);

    let (_, _, _, _) = tokio::join!(
        ip_svc_handle,
        stats_handle,
        tracker_handle,
        tracker_service_handle
    );
    info!("Exiting...");

    Ok(())
}

fn push_ports_to_map(bpf: &mut Bpf, ports: Vec<u16>) -> Result<(), anyhow::Error> {
    let mut protected_ports: HashMap<_, u16, u8> =
        HashMap::try_from(bpf.map_mut(PROTECTED_PORTS_MAP).unwrap()).unwrap();
    for port in ports {
        protected_ports.insert(&port, &0, 0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use cidr::Ipv4Cidr;
    use std::str::FromStr;

    #[test]
    fn test_scalar_conversion() {
        let string_scalar = Ipv4Cidr::from_str("1.3.5.7").unwrap();
        assert_eq!(string_scalar.network_length(), 32);
    }
}
