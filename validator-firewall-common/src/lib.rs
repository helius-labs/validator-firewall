#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeControls {
    pub global_enabled: bool,
    pub close_to_leader: bool,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuntimeControls {}
