#![no_std]

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Backend {
    pub saddr: u32,
    pub daddr: u32,
    pub dport: u32,
    pub ifindex: u16,
    // Cksum isn't required for UDP see:
    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    pub nocksum: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct VipKey { 
    pub vip: u32,
    pub port: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VipKey {}