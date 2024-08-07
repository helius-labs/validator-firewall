use aya::maps::{Array, Map};
use log::{error, info, warn};
use rangemap::RangeInclusiveSet;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::epoch_info::EpochInfo;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use validator_firewall_common::RuntimeControls;

#[derive(Copy, Clone, Debug)]
enum LeaderDistance {
    Close { begin: u64, current: u64, end: u64 },
    Far { current: u64 },
}

#[derive(Clone, Debug)]
enum LeaderTrackerState {
    NeedIdentity,
    NeedLeaderSchedule,
    Running { slots: RangeInclusiveSet<u64, u64> },
}

pub struct RPCLeaderTracker {
    exit_flag: Arc<AtomicBool>,
    rpc_client: RpcClient,
    slot_buffer: u64,
    id_override: Option<String>,
    leader_status: Arc<RwLock<Option<LeaderDistance>>>,
}

impl RPCLeaderTracker {
    pub fn new(
        exit_flag: Arc<AtomicBool>,
        rpc_client: RpcClient,
        slot_buffer: u64,
        id_override: Option<String>,
    ) -> Self {
        RPCLeaderTracker {
            exit_flag,
            rpc_client,
            slot_buffer,
            id_override,
            leader_status: Arc::new(RwLock::new(None)),
        }
    }

    async fn close_to_leader(&self) -> Option<LeaderDistance> {
        self.leader_status.read().await.clone()
    }
    pub async fn run(&self) {
        let mut current_epoch = 0u64;
        let mut max_slot = 0u64;

        let mut tracker_state = LeaderTrackerState::NeedIdentity;
        while !self.exit_flag.load(Ordering::Relaxed) {
            match tracker_state {
                LeaderTrackerState::NeedIdentity => {
                    if let Ok(_) = self.get_identity().await {
                        tracker_state = LeaderTrackerState::NeedLeaderSchedule;
                    } else {
                        warn!("Failed to get identity. Retrying in 5 seconds.");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                }
                LeaderTrackerState::NeedLeaderSchedule => {
                    let new_schedule = match self.refresh_leader_schedule().await {
                        Ok(sched) => sched,
                        Err(_) => {
                            warn!("Failed to get leader schedule. Retrying in 5 seconds.");
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    };

                    match self.rpc_client.get_epoch_info().await {
                        Ok(epoch_info) => {
                            current_epoch = epoch_info.epoch;
                            max_slot = epoch_info.absolute_slot - epoch_info.slot_index
                                + epoch_info.slots_in_epoch;
                            tracker_state = LeaderTrackerState::Running {
                                slots: new_schedule,
                            };
                            info!("New leader schedule loaded. Epoch {current_epoch} max slot {max_slot}");
                        }
                        Err(_) => {
                            error!("Failed to get epoch boundaries, leader schedule is incomplete");
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                }

                LeaderTrackerState::Running { ref slots } => {
                    match self
                        .rpc_client
                        .get_epoch_info_with_commitment(CommitmentConfig {
                            commitment: CommitmentLevel::Processed,
                        })
                        .await
                    {
                        Ok(epoch_info) => {
                            if epoch_info.epoch != current_epoch
                                || epoch_info.absolute_slot > max_slot
                            {
                                tracker_state = LeaderTrackerState::NeedLeaderSchedule;
                                info!("Epoch changed. Getting new leader schedule.");
                                {
                                    let mut guard = self.leader_status.write().await;
                                    *guard = None;
                                }
                                continue;
                            }

                            let idx = epoch_info.slot_index;
                            let mut guard = self.leader_status.write().await;
                            if let Some(leader_range) = slots.get(&idx) {
                                *guard = Some(LeaderDistance::Close {
                                    begin: *leader_range.start(),
                                    current: idx,
                                    end: *leader_range.end(),
                                });
                            } else {
                                *guard = Some(LeaderDistance::Far { current: idx });
                            }
                        }
                        Err(_) => {
                            error!("Failed to get epoch info.");
                            {
                                let mut guard = self.leader_status.write().await;
                                *guard = None;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            }
        }
    }

    async fn get_identity(&self) -> Result<String, ()> {
        match self.id_override.clone() {
            Some(id) => Ok(id),
            None => match self.rpc_client.get_identity().await {
                Ok(id) => Ok(id.to_string()),
                Err(e) => {
                    error!("Failed to get identity: {e}");
                    Err(())
                }
            },
        }
    }

    async fn refresh_leader_schedule(&self) -> Result<RangeInclusiveSet<u64, u64>, ()> {
        let my_id = self.get_identity().await?;
        return match self
            .rpc_client
            .get_leader_schedule_with_commitment(
                None,
                CommitmentConfig {
                    commitment: CommitmentLevel::Processed,
                },
            )
            .await
        {
            Err(e) => {
                error!("Failed to get leader schedule: {e}");
                Err(())
            }
            Ok(sched) => {
                if sched.is_none() {
                    error!("Failed to get leader schedule.");
                    return Err(());
                }
                if let Some(my_slots) = sched.unwrap().get(&my_id) {
                    let mut leader_ranges: RangeInclusiveSet<u64, u64> = RangeInclusiveSet::new();
                    for slot in my_slots {
                        let end: u64 = *slot as u64;

                        let range = end.saturating_sub(self.slot_buffer)..=end;
                        leader_ranges.insert(range);
                    }
                    leader_ranges.insert(0..=10);
                    // let rngs: Vec<Range<u64>> =leader_ranges.iter().collect();
                    info!("Leader ranges: {leader_ranges:?}");

                    Ok(leader_ranges)
                } else {
                    error!("No slots found for: {my_id}");
                    Err(())
                }
            }
        };
    }
}

pub struct CommandControlService {
    exit_flag: Arc<AtomicBool>,
    tracker: Arc<RPCLeaderTracker>,
    cnc_array: Map,
}

impl CommandControlService {
    pub fn new(exit_flag: Arc<AtomicBool>, tracker: Arc<RPCLeaderTracker>, cnc_array: Map) -> Self {
        CommandControlService {
            exit_flag,
            tracker,
            cnc_array,
        }
    }

    pub async fn run(&mut self) {
        let mut cnc_array: Array<_, RuntimeControls> =
            Array::try_from(&mut self.cnc_array).unwrap();
        let mut close_to_leader_enabled = false;
        cnc_array
            .set(
                0,
                RuntimeControls {
                    global_enabled: true,
                    close_to_leader: close_to_leader_enabled,
                },
                0,
            )
            .unwrap();

        while !self.exit_flag.load(Ordering::Relaxed) {
            let result = self.tracker.close_to_leader().await;
            match (result, close_to_leader_enabled) {
                (
                    Some(LeaderDistance::Close {
                        begin,
                        current,
                        end,
                    }),
                    false,
                ) => {
                    close_to_leader_enabled = true;
                    info!(
                        "Entering close to leader mode: Begin {begin} Current {current} End {end}"
                    );
                    let RuntimeControls {
                        global_enabled,
                        close_to_leader: _,
                    } = cnc_array.get(&0, 0).unwrap();
                    cnc_array
                        .set(
                            0,
                            RuntimeControls {
                                global_enabled,
                                close_to_leader: true,
                            },
                            0,
                        )
                        .unwrap();
                }
                (Some(LeaderDistance::Far { current }), true) => {
                    close_to_leader_enabled = false;
                    info!("Exiting close to leader mode: Current {current}");
                    let RuntimeControls {
                        global_enabled,
                        close_to_leader: _,
                    } = cnc_array.get(&0, 0).unwrap();
                    cnc_array
                        .set(
                            0,
                            RuntimeControls {
                                global_enabled,
                                close_to_leader: false,
                            },
                            0,
                        )
                        .unwrap();
                }
                (None, false) => {
                    close_to_leader_enabled = true;
                    warn!("Entering close to leader mode due to missing leader status");
                    let RuntimeControls {
                        global_enabled,
                        close_to_leader: _,
                    } = cnc_array.get(&0, 0).unwrap();
                    cnc_array
                        .set(
                            0,
                            RuntimeControls {
                                global_enabled,
                                close_to_leader: true,
                            },
                            0,
                        )
                        .unwrap();
                }
                _ => {}
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}
