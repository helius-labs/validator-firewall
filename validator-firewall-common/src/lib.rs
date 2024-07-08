#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeControls {
    pub global_enabled: bool,
    pub close_to_leader: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionStats {
    pub pkt_count: u64,
    pub blocked_pkt_count: u64,
    pub far_from_leader_pkt_count: u64,
    pub zero_rtt_pkt_count: u64,
}

pub enum StatType {
    All,
    Blocked,
    FarFromLeader,
    ZeroRtt,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuntimeControls {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionStats {}
