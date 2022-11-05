#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK},
    macros::{classifier, map},
    maps::{HashMap},
    programs::TcContext,
};
use aya_log_ebpf::info;
use memoffset::offset_of;

use tc_udp_redirect_common::{Backend, VipKey};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, udphdr};

const BUF_CAPACITY: usize = 256;

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_UDP: u8 = 17;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
//const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();

// Used to load from memory into rust accessible structure
#[repr(C)]
pub struct Buf {
    pub buf: [u8; BUF_CAPACITY],
}

#[map(name = "BACKENDS")] 
static mut BACKENDS: HashMap<VipKey, Backend> =
    HashMap::<VipKey, Backend>::with_max_entries(128, 0);


#[classifier(name="tc_udp_redirect")]
pub fn tc_udp_redirect(ctx: TcContext) -> i32 {
    match try_tc_udp_redirect(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    };

    return TC_ACT_OK
}

fn get_backend(key: VipKey) -> Option<&'static Backend> {
    unsafe { BACKENDS.get(&key) }
}

fn try_tc_udp_redirect(ctx: TcContext) -> Result<i32, i64> {    
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let protocol = ctx
        .load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))
        .map_err(|_| TC_ACT_PIPE)?;

    if protocol != IPPROTO_UDP{
        return Ok(TC_ACT_PIPE);
    }

    //let dst_ip = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);

    let ip_hdr: iphdr = ctx.load(ETH_HDR_LEN)?;

    let udp_header_offset = ETH_HDR_LEN + IP_HDR_LEN;

    //let dst_port = u16::from_be(ctx.load(offset + offset_of!(udphdr, dest))?);
    let udp_hdr: udphdr = ctx.load(udp_header_offset)?;
    
    let key = VipKey{
        vip: u32::from_be(ip_hdr.daddr), 
        port: (u16::from_be(udp_hdr.dest)) as u32,
    };

    let backend = get_backend(key);

    if backend.is_none() { 
        return Ok(TC_ACT_OK)
    }

    info!(&ctx, "Received a packet destined for svc ip: {} at port: {}", u32::from_be(ip_hdr.daddr), u16::from_be(udp_hdr.dest));

    // // Load Src/Dest IPs, update IP cksum, Zero Out UDP Cksum
    // ip_hdr.daddr = backend.daddr.to_be();
    // ip_hdr.check = 0;
    // ctx.l3_csum_replace(ETH_HDR_LEN + offset!(iphdr, check), 0, &ip_hdr, size_of(struct iphdr));
    // udp_hdr.dest = (backend.dport as u16).to_be();
    // udp_hdr.check = 0;
    // //Update IP Cksum

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
