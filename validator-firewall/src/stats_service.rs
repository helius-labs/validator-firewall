use aya::maps::{Map, PerCpuHashMap};
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct StatsService {
    exit: Arc<AtomicBool>,
    interval: u64,
    all_traffic_stats: Map,
    blocked_traffic_stats: Map,
}

impl StatsService {
    pub fn new(
        exit: Arc<AtomicBool>,
        interval: u64,
        all_traffic_stats: Map,
        blocked_traffic_stats: Map,
    ) -> Self {
        Self {
            exit,
            interval,
            all_traffic_stats,
            blocked_traffic_stats,
        }
    }

    pub async fn run(&self) {
        let co_exit = self.exit.clone();
        let all_traffic: PerCpuHashMap<_, u32, u64> =
            PerCpuHashMap::try_from(&self.all_traffic_stats).unwrap();
        let blocked_traffic: PerCpuHashMap<_, u32, u64> =
            PerCpuHashMap::try_from(&self.blocked_traffic_stats).unwrap();
        let report_interval = tokio::time::Duration::from_secs(self.interval);
        let mut blocked_last_sum = 0u64;
        let mut blocked_las_eval_time = std::time::Instant::now();
        let mut all_last_sum = 0u64;
        let mut all_las_eval_time = std::time::Instant::now();
        while !co_exit.load(Ordering::Relaxed) {
            // Get stats from the maps
            let mut all_sum = 0u64;
            for (addr, per_cpu_values) in all_traffic.iter().filter_map(|res| res.ok()) {
                let total: u64 = per_cpu_values.iter().sum();
                let native_addr = std::net::Ipv4Addr::from(u32::from_ne_bytes(addr.to_ne_bytes()));
                all_sum += total;
                info!("total_packets: {:?} = {:?}", native_addr, total);
            }
            info!(
                "All traffic summary: {} pkts last_interval {} pkts {} pkts/s",
                all_sum,
                all_sum - all_last_sum,
                (all_sum - all_last_sum) / all_las_eval_time.elapsed().as_secs().max(1)
            );
            all_last_sum = all_sum;
            all_las_eval_time = std::time::Instant::now();

            let mut blocked_sum = 0u64;
            for (addr, per_cpu_values) in blocked_traffic.iter().filter_map(|res| res.ok()) {
                let total: u64 = per_cpu_values.iter().sum();
                let native_addr = std::net::Ipv4Addr::from(u32::from_ne_bytes(addr.to_ne_bytes()));
                blocked_sum += total;
                info!("dropped_packets: {:?} = {:?}", native_addr, total);
            }
            info!(
                "Blocked traffic summary: {} pkts last_interval {} pkts {} pkts/s",
                blocked_sum,
                blocked_sum - blocked_last_sum,
                (blocked_sum - blocked_last_sum) / blocked_las_eval_time.elapsed().as_secs().max(1)
            );
            blocked_last_sum = blocked_sum;
            blocked_las_eval_time = std::time::Instant::now();

            tokio::time::sleep(report_interval).await;
        }
    }
}
