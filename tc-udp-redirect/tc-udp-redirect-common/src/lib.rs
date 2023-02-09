#![no_std]

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Backend {
    pub daddr: u32,
    pub dport: u32,
    pub ifindex: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

// #[derive(Copy, Clone, Debug)]
// #[repr(C)]
// pub struct ConTuple { 
//     pub src_address: u32, // 4 bytes
//     pub dst_address: u32, // 4 bytes
//     pub protocol: u16,  // 2 bytes
//     pub pad: u16,
// }

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for ConTuple {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct VipKey { 
    pub vip: u32,
    pub port: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VipKey {}