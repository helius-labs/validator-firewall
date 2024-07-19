use aya::maps::{HashMap, Map};
use cidr::Ipv4Cidr;
use duckdb::params;
use log::{debug, error, info};
use rangemap::RangeInclusiveSet;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use std::collections::HashSet;
use std::net::{Ipv4Addr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

pub struct HttpDenyListClient {
    url: String,
}

impl HttpDenyListClient {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl DenyListClient for HttpDenyListClient {
    async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        let client = reqwest::Client::new();
        match client.get(&self.url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    let allow_list: Vec<Ipv4Cidr> = resp.json().await.unwrap();
                    info!(
                        "Retrieved {} IPs from external ip service",
                        allow_list.len()
                    );
                    Ok(allow_list)
                } else {
                    error!("Failed to decode deny list from external ip service.");
                    Err(())
                }
            }
            Err(_) => Err(()),
        }
    }
}

pub struct DuckDbDenyListClient {
    conn: Arc<Mutex<duckdb::Connection>>,
    query: String,
}

impl DuckDbDenyListClient {
    pub fn new(query: String) -> Self {
        Self {
            conn: Arc::new(Mutex::new(duckdb::Connection::open_in_memory().unwrap())),
            query,
        }
    }

    async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        info!("Executing query: {}", self.query);

        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(&self.query).unwrap();
        let mut rows = stmt.query(params![]).unwrap();
        let mut deny_list = Vec::new();
        let mut count = 0;
        while let Some(row) = rows.next().unwrap() {
            let ip: u32 = row.get(0).unwrap();
            let converted: Ipv4Addr = ip.into();

            let cidr = Ipv4Cidr::new(converted, 32).unwrap();
            deny_list.push(cidr);
            count += 1;
        }

        info!("Retrieved {} IPs from query", count);
        Ok(deny_list)
    }
}

impl DenyListClient for DuckDbDenyListClient {
    async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        self.get_deny_list().await
    }
}

pub struct NoOpDenyListClient;

impl DenyListClient for NoOpDenyListClient {
    async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        Ok(Vec::new())
    }
}

pub trait DenyListClient {
    async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()>;
}

pub struct DenyListService<T: DenyListClient> {
    deny_list_client: T,
}

impl<T: DenyListClient> DenyListService<T> {
    pub fn new(allow_list_client: T) -> Self {
        Self {
            deny_list_client: allow_list_client,
        }
    }

    pub async fn get_deny_list(&self) -> Result<Vec<Ipv4Cidr>, ()> {
        self.deny_list_client.get_deny_list().await
    }
}

pub struct DenyListStateUpdater<T: DenyListClient> {
    exit_flag: Arc<AtomicBool>,
    allow_service: Arc<DenyListService<T>>,
    allow_ranges: RangeInclusiveSet<u32>,
    deny_ranges: RangeInclusiveSet<u32>,
}

pub fn to_range(ip: Ipv4Cidr) -> RangeInclusive<u32> {
    let start_addr: u32 = ip.first_address().try_into().unwrap();
    let end_addr: u32 = ip.last_address().try_into().unwrap();
    start_addr..=end_addr
}

impl<T: DenyListClient> DenyListStateUpdater<T> {
    pub fn new(
        exit_flag: Arc<AtomicBool>,
        allow_service: Arc<DenyListService<T>>,
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
        let mut deny_list: HashMap<_, u32, u8> = HashMap::try_from(allow_list).unwrap();
        let mut dynamic_deny_set = HashSet::new();

        while !self.exit_flag.load(Ordering::Relaxed) {
            if let Ok(nodes) = self.allow_service.get_deny_list().await {
                dynamic_deny_set.clear();
                for ip4addr in nodes.iter().flat_map(|cidr| cidr.into_iter().addresses()) {
                    let ip_numeric: u32 = ip4addr.try_into().expect("Received invalid ip address");
                    if !self.is_allowed(&ip_numeric) {
                        dynamic_deny_set.insert(ip_numeric);
                    }
                }

                let to_remove = {
                    deny_list
                        .iter()
                        .filter_map(|r| r.ok())
                        .filter(|(x, _)| !dynamic_deny_set.contains(x))
                        .filter(|(x, _)| !self.is_denied(x))
                        .map(|x| x.0)
                        .collect::<Vec<u32>>()
                };

                debug!("Pruning {} ips from deny list", to_remove.len());
                for ip in to_remove {
                    deny_list.remove(&ip).unwrap();
                }

                {
                    for ip in dynamic_deny_set.iter() {
                        if !deny_list.get(ip, 0).is_ok() {
                            deny_list.insert(ip, 0, 0).unwrap();
                        }
                    }
                }
            } else {
                error!("Error fetching deny list from RPC");
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
