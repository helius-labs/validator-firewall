use aya::maps::{HashMap, Map, MapData};
use log::debug;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

pub struct GossipWatcher {
    exit_flag: Arc<AtomicBool>,
    rpc_client: Arc<RpcClient>,
    static_overrides: Arc<HashSet<u32>>,
    // allow_list: Map, //Annoying type-erased BPF Map <u32, u8>
}

impl GossipWatcher {
    pub fn new(
        exit_flag: Arc<AtomicBool>,
        rpc_client: Arc<RpcClient>,
        static_overrides: Arc<HashSet<u32>>,
        // allow_list: Map,
    ) -> Self {
        Self {
            exit_flag,
            rpc_client,
            static_overrides,
            // allow_list,
        }
    }
    pub async fn run(&self, allow_list: Map) {
        let mut allow_list: HashMap<_, u32, u8> = HashMap::try_from(allow_list).unwrap();
        for ip in self.static_overrides.iter() {
            allow_list.insert(ip, 0, 0).unwrap();
        }
        let mut gossip_set = HashSet::new();

        while !self.exit_flag.load(Ordering::Relaxed) {
            if let Ok(nodes) = self.rpc_client.get_cluster_nodes().await {
                gossip_set.clear();
                for node in nodes.iter().filter(|n| n.gossip.is_some()) {
                    match node.gossip.as_ref().unwrap() {
                        SocketAddr::V4(sock) => {
                            let ip_numeric: u32 = (*sock.ip())
                                .try_into()
                                .expect("Received invalid ip address");
                            gossip_set.insert(ip_numeric);
                        }
                        SocketAddr::V6(_) => {}
                    }
                }

                let to_remove = {
                    allow_list
                        .iter()
                        .filter_map(|r| r.ok())
                        .filter(|(x, _)| {
                            !gossip_set.contains(x) && !self.static_overrides.contains(x)
                        })
                        .map(|x| x.0)
                        .collect::<Vec<u32>>()
                };
                debug!("Pruning {} ips from allow list", to_remove.len());

                for ip in to_remove {
                    allow_list.remove(&ip).unwrap();
                }

                {
                    for ip in gossip_set.iter() {
                        if !allow_list.get(ip, 0).is_ok() {
                            allow_list.insert(ip, 0, 0).unwrap();
                        }
                    }
                }
            }

            sleep(Duration::from_secs(10)).await;
        }
    }
}
