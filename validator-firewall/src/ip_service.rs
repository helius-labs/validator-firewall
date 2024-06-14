use aya::maps::{HashMap, Map};
use cidr::Ipv4Cidr;
use log::{debug, error};
use rangemap::RangeInclusiveSet;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub struct GossipAllowListClient {
    rpc_client: RpcClient,
}

impl GossipAllowListClient {
    pub fn new(rpc_client: RpcClient) -> Self {
        Self { rpc_client }
    }
}
impl AllowListClient for GossipAllowListClient {
    async fn get_allow_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        let mut gossip_set = HashSet::new();
        if let Ok(nodes) = self.rpc_client.get_cluster_nodes().await {
            for node in nodes.iter().filter(|n| n.gossip.is_some()) {
                match node.gossip.as_ref().unwrap() {
                    SocketAddr::V4(sock) => {
                        let cidr = Ipv4Cidr::new(*sock.ip(), 32).unwrap();
                        gossip_set.insert(cidr);
                    }
                    SocketAddr::V6(_) => {}
                }
            }

            if gossip_set.is_empty() {
                return Err(());
            }
            Ok(gossip_set.into_iter().collect())
        } else {
            Err(())
        }
    }
}

pub trait AllowListClient {
    async fn get_allow_list(&self) -> Result<Vec<Ipv4Cidr>, ()>;
}

pub struct AllowListService<T: AllowListClient> {
    allow_list_client: T,
}

impl<T: AllowListClient> AllowListService<T> {
    pub fn new(allow_list_client: T) -> Self {
        Self { allow_list_client }
    }

    pub async fn get_allow_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        self.allow_list_client.get_allow_list().await
    }
}

pub struct AllowListStateUpdater<T: AllowListClient> {
    exit_flag: Arc<AtomicBool>,
    allow_service: Arc<AllowListService<T>>,
    allow_ranges: RangeInclusiveSet<u32>,
    deny_ranges: RangeInclusiveSet<u32>,
}

pub fn to_range(ip: Ipv4Cidr) -> RangeInclusive<u32> {
    let start_addr: u32 = ip.first_address().try_into().unwrap();
    let end_addr: u32 = ip.last_address().try_into().unwrap();
    start_addr..=end_addr
}

impl<T: AllowListClient> AllowListStateUpdater<T> {
    pub fn new(
        exit_flag: Arc<AtomicBool>,
        allow_service: Arc<AllowListService<T>>,
        static_overrides: Arc<(HashSet<Ipv4Cidr>, HashSet<Ipv4Cidr>)>,
    ) -> Self {
        Self {
            exit_flag,
            allow_service,
            allow_ranges: {
                RangeInclusiveSet::from_iter(
                    static_overrides.clone().0.iter().map(|ip| to_range(*ip)),
                )
            },
            deny_ranges: {
                RangeInclusiveSet::from_iter(static_overrides.1.iter().map(|ip| to_range(*ip)))
            },
        }
    }

    pub fn is_denied(&self, addr: &u32) -> bool {
        self.deny_ranges.contains(addr)
    }

    pub fn is_allowed(&self, addr: &u32) -> bool {
        self.allow_ranges.contains(addr)
    }

    pub async fn run(&self, allow_list: Map) {
        let mut allow_list: HashMap<_, u32, u8> = HashMap::try_from(allow_list).unwrap();
        let mut dynamic_allow_set = HashSet::new();

        while !self.exit_flag.load(Ordering::Relaxed) {
            if let Ok(nodes) = self.allow_service.get_allow_list().await {
                dynamic_allow_set.clear();
                for ip4addr in nodes.iter().flat_map(|cidr| cidr.into_iter().addresses()) {
                    let ip_numeric: u32 = ip4addr.try_into().expect("Received invalid ip address");
                    if !self.is_denied(&ip_numeric) {
                        dynamic_allow_set.insert(ip_numeric);
                    }
                }

                let to_remove = {
                    allow_list
                        .iter()
                        .filter_map(|r| r.ok())
                        .filter(|(x, _)| !dynamic_allow_set.contains(x) && !self.is_allowed(x))
                        .map(|x| x.0)
                        .collect::<Vec<u32>>()
                };
                debug!("Pruning {} ips from allow list", to_remove.len());

                for ip in to_remove {
                    allow_list.remove(&ip).unwrap();
                }

                {
                    for ip in dynamic_allow_set.iter() {
                        if !allow_list.get(ip, 0).is_ok() {
                            allow_list.insert(ip, 0, 0).unwrap();
                        }
                    }
                }
            } else {
                error!("Error fetching allow list from RPC");
            }

            sleep(Duration::from_secs(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rangemap::RangeInclusiveSet;
    use std::str::FromStr;

    #[test]
    fn test_inet_ranges() {
        let mut deny_range = RangeInclusiveSet::new();
        let single_host = Ipv4Cidr::from_str("1.1.1.1/32").unwrap();

        let start_addr: u32 = single_host.first().address().try_into().unwrap();
        let end_addr: u32 = single_host.last().address().try_into().unwrap();
        deny_range.insert(start_addr..=end_addr);

        assert!(deny_range.contains(&start_addr));
    }

    #[test]
    fn test_range_coalescing() {
        let mut deny_range = RangeInclusiveSet::new();
        let first_host = Ipv4Cidr::from_str("1.1.1.1/32").unwrap();
        let adjacent_host = Ipv4Cidr::from_str("1.1.1.2/32").unwrap();

        let bare_host = Ipv4Cidr::from_str("192.168.1.1").unwrap();
        assert!(bare_host.is_host_address());

        let start_addr: u32 = first_host.first().address().try_into().unwrap();
        let end_addr: u32 = first_host.last().address().try_into().unwrap();
        deny_range.insert(start_addr..=end_addr);

        let start_addr: u32 = adjacent_host.first().address().try_into().unwrap();
        let end_addr: u32 = adjacent_host.last().address().try_into().unwrap();
        deny_range.insert(start_addr..=end_addr);
        assert_eq!(deny_range.len(), 1);

        println!("{:?}", deny_range);
    }
}
