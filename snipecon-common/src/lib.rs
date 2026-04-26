#![no_std]

// This is where we will put shared structures 
// that both the Kernel and the Dashboard understand.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketLog {
    pub ipv4_src: u32,
    pub ipv4_dst: u32,
    pub action: u32,
}
