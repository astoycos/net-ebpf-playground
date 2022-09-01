#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    maps::{HashMap, PerfEventArray},

};
use aya_log_ebpf::info;
use basic_node_firewall_common::{PacketLog, PacketFiveTuple};

use core::mem;
use memoffset::offset_of;

mod bindings;
use bindings::{ethhdr, iphdr, tcphdr};

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const IPPROTO_TCP: u8 = 6;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<PacketFiveTuple, u32> =
    HashMap::<PacketFiveTuple, u32>::with_max_entries(1024, 0);

#[xdp(name="basic_node_firewall")]
pub fn basic_node_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_basic_node_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// (2)
fn block_ip(key: &mut PacketFiveTuple) -> bool {
    unsafe { BLOCKLIST.get(key).is_some() }
}

unsafe fn try_basic_node_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
    });
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    //Protocol isn't in NE
    let l4_proto = unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))?
    };

    if l4_proto != IPPROTO_TCP{ 
        return Ok(xdp_action::XDP_PASS);
    }

    let source_ip = u32::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?
    });

    let dest_ip = u32::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))?
    });

    let source_port = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
    });

    let dest_port = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
    });

    let mut firewall_key = PacketFiveTuple { 
        src_address: source_ip, 
        dst_address: dest_ip,
        src_port: source_port,
        dst_port: dest_port, 
        protocol: l4_proto,
        _pad: [0, 0, 0],
    };
        
    let action = if block_ip(&mut firewall_key) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    
    if action == xdp_action::XDP_DROP {
        let log_entry = PacketLog {
            ipv4_address: source_ip,
            action: action,
        };
        
        unsafe {
            EVENTS.output(&ctx, &log_entry, 0);
        }
    }
    
    Ok(action)
}


