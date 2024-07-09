use aya::maps::{Map, MapData, MapIter, PerCpuHashMap, PerCpuValues};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;
use validator_firewall_common::StatType::{All, Blocked};
use validator_firewall_common::{ConnectionStats, StatType};

pub struct StatsService {
    exit: Arc<AtomicBool>,
    interval: u64,
    traffic_stats: Map,
}

impl StatsService {
    pub fn new(exit: Arc<AtomicBool>, interval: u64, traffic_stats: Map) -> Self {
        Self {
            exit,
            interval,
            traffic_stats,
        }
    }

    pub fn prepare_stats(
        map: MapIter<
            u32,
            PerCpuValues<ConnectionStats>,
            PerCpuHashMap<&MapData, u32, ConnectionStats>,
        >,
        stat_type: StatType,
    ) -> Vec<(Ipv4Addr, u64)> {
        let mut pairs: Vec<(Ipv4Addr, u64)> = map
            .filter_map(|res| res.ok())
            .map(|(addr, per_cpu)| {
                let parsed_addr = std::net::Ipv4Addr::from(u32::from_ne_bytes(addr.to_ne_bytes()));

                (
                    parsed_addr,
                    per_cpu
                        .iter()
                        .map(|x| match stat_type {
                            StatType::All => x.pkt_count,
                            StatType::Blocked => x.blocked_pkt_count,
                            StatType::FarFromLeader => x.far_from_leader_pkt_count,
                            StatType::ZeroRtt => x.zero_rtt_pkt_count,
                        })
                        .sum::<u64>(),
                )
            })
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    pub async fn run(&self) {
        let co_exit = self.exit.clone();
        let traffic_stats: PerCpuHashMap<_, u32, ConnectionStats> =
            PerCpuHashMap::try_from(&self.traffic_stats).unwrap();
        let report_interval = tokio::time::Duration::from_secs(self.interval);
        let mut blocked_last_sum = 0u64;
        let mut blocked_las_eval_time = std::time::Instant::now();
        let mut all_last_sum = 0u64;
        let mut all_las_eval_time = std::time::Instant::now();

        while !co_exit.load(Ordering::Relaxed) {
            // Get stats from the maps
            let mut all_sum = 0u64;
            let mut log_limit = 100;
            for (addr, total) in Self::prepare_stats(traffic_stats.iter(), All) {
                all_sum += total;
                if log_limit > 0 {
                    info!("total_packets: {:?} = {:?}", addr, total);
                    log_limit -= 1;
                }
            }

            let rate = (all_sum - all_last_sum) / all_las_eval_time.elapsed().as_secs().max(1);
            let delta = all_sum - all_last_sum;

            info!(
                traffic_type = "All",
                rate = rate,
                delta = delta,
                total = all_sum,
                "All traffic summary: {} pkts last_interval {} pkts {} pkts/s",
                all_sum,
                delta,
                rate
            );
            all_last_sum = all_sum;
            all_las_eval_time = std::time::Instant::now();

            let mut blocked_sum = 0u64;
            let mut log_limit = 100;
            for (addr, total) in Self::prepare_stats(traffic_stats.iter(), Blocked) {
                blocked_sum += total;
                if log_limit > 0 {
                    info!("dropped_packets: {:?} = {:?}", addr, total);
                    log_limit -= 1;
                }
            }

            let rate =
                (blocked_sum - blocked_last_sum) / blocked_las_eval_time.elapsed().as_secs().max(1);
            let delta = blocked_sum - blocked_last_sum;
            info!(
                traffic_type = "Blocked",
                rate = rate,
                delta = delta,
                total = blocked_sum,
                "Blocked traffic summary: {} pkts last_interval {} pkts {} pkts/s",
                blocked_sum,
                delta,
                rate
            );
            blocked_last_sum = blocked_sum;
            blocked_las_eval_time = std::time::Instant::now();

            tokio::time::sleep(report_interval).await;
        }
    }
}
