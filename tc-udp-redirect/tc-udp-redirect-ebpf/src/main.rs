#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT, TC_ACT_OK},
    macros::{classifier, map},
    maps::{HashMap},
    programs::TcContext,
    helpers::{bpf_csum_diff, bpf_redirect_neigh}
};
use aya_log_ebpf::info;
use memoffset::offset_of;
use mem::size_of;

use tc_udp_redirect_common::{Backend, VipKey}
;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, udphdr, icmphdr};

const ETH_P_IP: u16 = 0x0800;

const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const ICMP_HDR_LEN: usize = mem::size_of::<icmphdr>();
const ICMP_CKSUM_LEN: usize = ETH_HDR_LEN + IP_HDR_LEN + 2;


// Gives us raw pointers to a specific offset in the packet
#[inline(always)]
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

#[map(name = "CONNTRACK")] 
static mut CONNTRACK: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(128, 0);

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

fn insert_conntrack(key: u32, entry: u32) -> Result<(), i64>{
    unsafe { CONNTRACK.insert(&key, &entry, 0 as u64) }
}

fn get_conntrack(key: u32) -> Option<&'static u32> {
    unsafe { CONNTRACK.get(&key) }
}

fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4
    {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}

// Make sure ip_forwarding is enabled on the interface this it attached to
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

    let ip_hdr: *mut iphdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN) }?;

    let udp_header_offset = ETH_HDR_LEN + IP_HDR_LEN;

    if protocol == IPPROTO_ICMP { 
        // Return Path hack
        info!(&ctx, "Received an ICMP packet destined for ip: {:X}",
        u32::from_be(unsafe { (*ip_hdr).daddr }),
        ); 

        let icmp_hdr: *mut icmphdr = unsafe { ptr_at(&ctx, udp_header_offset)? };
        // let key = ConTuple{
        //     dst_address: backend.daddr.clone(), 
        //     src_address: unsafe { (*ip_hdr).saddr },
        //     src_port: unsafe { (*udp_hdr).source },
        //     dst_port: backend.dport.clone() as u16,
        //     protocol: protocol as u16,
        //     pad: 0,
        // };

        // We only care about redirecting port unrechable messages currently so a 
        // UDP client can tell when the server is shutdown
        if unsafe { (*icmp_hdr).type_ } != 3 { 
            return Ok(TC_ACT_OK);
        }   

        let new_src = get_conntrack(unsafe { (*ip_hdr).daddr }).ok_or(TC_ACT_OK)?;

        // info!(&ctx, "SNATED an ICMP packet with from: {:X} to: {:X}",
        // u32::from_be(unsafe { (*ip_hdr).saddr }),
        // u32::from_be(*new_src),
        // ); 

        unsafe { (*ip_hdr).saddr = *new_src }

        unsafe { (*ip_hdr).check = 0 };
        let full_cksum = unsafe { bpf_csum_diff(mem::MaybeUninit::zeroed().assume_init(),0 ,ip_hdr as *mut u32, size_of::<iphdr>() as u32, 0)} as u64;
        unsafe { (*ip_hdr).check = csum_fold_helper(full_cksum) };   

        // Get inner ipheader
        let icmp_ip_hdr: *mut iphdr  = unsafe { ptr_at(&ctx, udp_header_offset + ICMP_HDR_LEN)}?;
        info!(&ctx, "Received an ICMP packet with inner packet dst: {:X}",
        u32::from_be(unsafe { (*icmp_ip_hdr).daddr }),
        );

        unsafe { (*icmp_ip_hdr).daddr = *new_src };

        unsafe { (*icmp_ip_hdr).check = 0 };
        let full_cksum = unsafe { bpf_csum_diff(mem::MaybeUninit::zeroed().assume_init(),0 ,icmp_ip_hdr as *mut u32, size_of::<iphdr>() as u32, 0)} as u64;
        unsafe { (*icmp_ip_hdr).check = csum_fold_helper(full_cksum) };

        //ctx.l4_csum_replace(ICMP_CKSUM_LEN, unsafe{ (*icmp_ip_hdr).daddr as u64 }, *new_src as u64, 0);
        
        //ctx.store(udp_header_offset + ICMP_HDR_LEN + offset_of!(iphdr, daddr), new_src, 0);
        //unsafe { (*icmp_ip_hdr).daddr = *new_src }
        //unsafe {bpf_l4_csum_replace(ctx.skb.skb, (udp_header_offset + offset_of!(icmphdr, checksum)).try_into().unwrap(), old_daddr as u64, *new_src as u64, size_of::<u16>() as u64)};
        //unsafe { (*icmp_ip_hdr).daddr = *new_src }

        //unsafe { (*icmp_hdr).checksum = 0 }
        // let full_cksum_icmp = unsafe { bpf_csum_diff(mem::MaybeUninit::zeroed().assume_init(),0 ,icmp_hdr as *mut u32, size_of::<icmphdr>() as u32, 0)} as u64;
        // unsafe { (*icmp_hdr).checksum = csum_fold_helper(full_cksum_icmp) };

        return Ok(TC_ACT_OK);
    }
        
    if protocol != IPPROTO_UDP {
        return Ok(TC_ACT_PIPE);
    }

    let udp_hdr: *mut udphdr = unsafe { ptr_at(&ctx, udp_header_offset)? };
    
    let original_daddr = unsafe { (*ip_hdr).daddr };

    let key = VipKey{
        vip: u32::from_be(original_daddr), 
        port: (u16::from_be(unsafe { (*udp_hdr).dest })) as u32,
    };

    info!(&ctx, "Received a packet destined for svc ip: {:X} at port: {}",
        u32::from_be(original_daddr),
        u16::from_be(unsafe { (*udp_hdr).dest })
    );

    let backend = get_backend(key).ok_or(TC_ACT_OK)?;

    info!(&ctx, "Backends Received a packet destined for svc ip: {:X} at port: {}",
        u32::from_be(original_daddr),
        u16::from_be(unsafe { (*udp_hdr).dest })
    );

    // let conntrack_entry_key = ConTuple{
    //         dst_address: backend.daddr.clone(), 
    //         src_address: unsafe { (*ip_hdr).saddr },
    //         src_port: unsafe { (*udp_hdr).source },
    //         dst_port: backend.dport.clone() as u16,
    //         protocol: protocol as u16,
    //         pad: 0,
    //     };
    
    // let conntrack_entry = ConTuple{
    //     dst_address: unsafe { (*ip_hdr).saddr }, 
    //     src_address: original_daddr,
    //     src_port: backend.dport.clone() as u16,
    //     dst_port: unsafe { (*udp_hdr).dest },
    //     protocol: protocol as u16,
    //     pad: 0,
    // };

    // Keep track of original dst IP
    insert_conntrack(unsafe { (*ip_hdr).saddr }, original_daddr)?;

    // Update destination IP
    unsafe { (*ip_hdr).daddr = backend.daddr.to_be(); }

    if (ctx.data() + ETH_HDR_LEN + size_of::<iphdr>()) > ctx.data_end() {
        info!(&ctx, "Iphdr is out of bounds");
        return Ok(TC_ACT_OK);
    }
    
    // Calculate l3 cksum
    // TODO(astoycos) use l3_cksum_replace instead
    unsafe { (*ip_hdr).check = 0 };
    let full_cksum = unsafe { bpf_csum_diff(mem::MaybeUninit::zeroed().assume_init(),0 ,ip_hdr as *mut u32, size_of::<iphdr>() as u32, 0)} as u64;
    unsafe { (*ip_hdr).check = csum_fold_helper(full_cksum) };    

    // Update destination port
    unsafe { (*udp_hdr).dest = (backend.dport as u16).to_be() };
    // Kernel allows UDP packet with unset checksums
    unsafe { (*udp_hdr).check = 0};

    let action = unsafe{ bpf_redirect_neigh(backend.ifindex as u32,  mem::MaybeUninit::zeroed().assume_init(), 0, 0) };

    info!(&ctx, "redirect action: {}", action);

    Ok(action as i32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
