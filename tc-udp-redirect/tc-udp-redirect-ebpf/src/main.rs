#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK},
    macros::{classifier, map},
    maps::{HashMap},
    programs::TcContext,
    helpers::{bpf_csum_diff, bpf_l3_csum_replace}
};
use aya_log_ebpf::info;
use memoffset::offset_of;
use mem::size_of;

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

#[inline(always)] // (2)
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i64> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_OK.into());
    }

    Ok((start + offset) as *mut T)
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

fn csum_fold_helper(mut csum: u64) -> u16 {
    for i in 0..4
    {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}

fn try_tc_udp_redirect(mut ctx: TcContext) -> Result<i32, i64> {    
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

    let ip_hdr: *mut iphdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN) }?;

    let udp_header_offset = ETH_HDR_LEN + IP_HDR_LEN;

    //let dst_port = u16::from_be(ctx.load(offset + offset_of!(udphdr, dest))?);
    let udp_hdr: *mut udphdr = unsafe { ptr_at(&ctx, udp_header_offset)? };
    
    let key = VipKey{
        vip: u32::from_be(unsafe { (*ip_hdr).daddr }), 
        port: (u16::from_be(unsafe { (*udp_hdr).dest })) as u32,
    };

    let backend = get_backend(key).ok_or(TC_ACT_OK)?;

    info!(&ctx, "Received a packet destined for svc ip: {:X} at port: {}",
        u32::from_be(unsafe { (*ip_hdr).daddr }),
        u16::from_be(unsafe { (*udp_hdr).dest })
    );

    // Load Src/Dest IPs, update IP cksum, Zero Out UDP Cksum
    // unsafe { (*ip_hdr).check = 0; }
    //let raw_backend_daddr = backend.daddr.to_be() as *mut _;
    //let l3_sum = unsafe { bpf_csum_diff( (*ip_hdr).daddr as *mut u32,4, backend.daddr.to_be() as *mut u32, 4, 0) };
    //unsafe { (*ip_hdr).daddr = backend.daddr.to_be(); }
 
    //ctx.l3_csum_replace(ETH_HDR_LEN + offset_of!(iphdr, check), 0, 100 as u64, 0);
    

    //ctx.l3_csum_replace(ETH_HDR_LEN + offset_of!(iphdr, check), unsafe { (*ip_hdr).daddr } as u64, backend.daddr.to_be() as u64, 4);
    unsafe { (*ip_hdr).daddr = backend.daddr.to_be(); }
    //unsafe { (*ip_hdr).check = 0; }

    if (ctx.data() + ETH_HDR_LEN + size_of::<iphdr>()) > ctx.data_end() {
        info!(&ctx, "Iphdr is out of bounds");
        return Ok(TC_ACT_OK);
    }
    
    let mut full_cksum = unsafe { bpf_csum_diff(0 as *mut _,0,ptr_at(&ctx, ETH_HDR_LEN)?, size_of::<iphdr>() as u32, 0)} as u64;
    info!(&ctx, "full check = {:X}", full_cksum);

    let folded_cksum = csum_fold_helper(full_cksum);
    info!(&ctx, "folded check = {:X}", folded_cksum);

    unsafe { (*ip_hdr).check = folded_cksum };
    //unsafe { (*ip_hdr).check = bpf_csum_diff(0 as *mut _,0,ptr_at(&ctx, ETH_HDR_LEN)?, size_of::<iphdr>() as u32, 0) as u16; }
    //ctx.l3_csum_replace(ip_hdr + offset_of(iphdr_daddr), 0, raw_iphdr as u64, size_of::<iphdr>() as u64);
    // ip_hdr.check = bpf_csum_diff(0,0,raw_iphdr, size_of::<iphdr>() as u32,0);
    info!(&ctx, "Updated Iphdr check = {:X}", unsafe { (*ip_hdr).check });
    // udp_hdr.dest = (backend.dport as u16).to_be();
    unsafe { (*udp_hdr).dest = (backend.dport as u16).to_be() };
    unsafe { (*udp_hdr).check = 0};
    // // Reload iphdr and udphdr with updates
    // ctx.store(ETH_HDR_LEN, &ip_hdr, 0);
    // ctx.store(udp_header_offset, &udp_hdr, 0);

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
