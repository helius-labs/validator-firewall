mod config;
mod ip_service;
mod ip_service_http;

use crate::config::{load_static_overrides, NameAddressPair};
use crate::ip_service::{DenyListService, DenyListStateUpdater};
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
    #[clap(short, long)]
    bearer_token: Option<String>,
    #[clap(short, long, default_value = "11525")]
    port: u16,
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

    let app_state = Arc::new(IPState::new());


    for node in static_overrides.0.iter() {
        app_state.add_http_node(node.clone()).await;
    }

    for node in static_overrides.1.iter() {
        app_state.add_blocked_node(node.clone()).await;
    }

    info!("Starting IP service on port {}", config.port.clone());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await
        .unwrap();
    let app = create_router(app_state.clone(), config.bearer_token);

    Ok(axum::serve(listener, app.into_make_service())
        .await
        .unwrap())
}
