mod config;
mod ip_service;
mod ip_service_http;

use crate::config::{load_static_overrides, NameAddressPair};
use crate::ip_service::{AllowListService, AllowListStateUpdater, GossipAllowListClient};
use crate::ip_service_http::{create_router, IPState};
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use cidr::Ipv4Cidr;
use clap::Parser;
use log::{error, info};
use serde::{Deserialize, Serialize};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug, Parser)]
struct IpServiceConfig {
    #[clap(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_endpoint: String,
    #[clap(short, long)]
    static_overrides: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let exit_flag = Arc::new(AtomicBool::new(false));
    let config = IpServiceConfig::parse();
    tracing_subscriber::fmt().json().init();

    let rpc_endpoint = config.rpc_endpoint.clone();

    let static_overrides = {
        let mut local_allow = HashSet::new();
        let mut local_deny = HashSet::new();

        // Load static overrides if provided
        if let Some(path) = config.static_overrides {
            let overrides = load_static_overrides(path).unwrap();
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

    let gossip_svc = Arc::new(AllowListService::new(GossipAllowListClient::new(
        RpcClient::new_with_commitment(rpc_endpoint.clone(), CommitmentConfig::processed()),
    )));

    let app_state = Arc::new(IPState::new());

    let co_app_state = app_state.clone();
    let co_gossip_svc = gossip_svc.clone();
    let co_exit_flag = exit_flag.clone();
    tokio::spawn(async move {
        while !co_exit_flag.load(std::sync::atomic::Ordering::Relaxed) {
            match co_gossip_svc.get_allow_list().await {
                Ok(nodes) => {
                    let set_nodes: HashSet<Ipv4Cidr> = nodes.into_iter().collect();
                    co_app_state.set_gossip_nodes(set_nodes).await;
                }
                Err(_) => {
                    error!("Failed to retrieve gossip nodes.")
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });

    for node in static_overrides.0.iter() {
        app_state.add_http_node(node.clone()).await;
    }

    for node in static_overrides.1.iter() {
        app_state.add_blocked_node(node.clone()).await;
    }

    let listener = tokio::net::TcpListener::bind("0.0.0.0:11525")
        .await
        .unwrap();
    let app = create_router(app_state.clone());

    Ok(axum::serve(listener, app.into_make_service())
        .await
        .unwrap())
}
