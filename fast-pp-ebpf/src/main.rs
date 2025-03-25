#![no_std]
#![no_main]

use core::net::IpAddr;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, XskMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error};

use fast_pp_common::IpNetwork;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[map]
static XSK_MAP: XskMap = XskMap::with_max_entries(8, 0);

#[map]
static FILTER: Array<IpNetwork> = Array::with_max_entries(32, 0);

#[xdp]
pub fn xdp_example(ctx: XdpContext) -> u32 {
    match try_xdp_example(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_example(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    let dst_addr = match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => get_dst_v4(&ctx)?,
        EtherType::Ipv6 => get_dst_v6(&ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };
    debug!(&ctx, "DST IP: {}", dst_addr);

    if !matches_filter(dst_addr) {
        debug!(&ctx, "Packet does not match filter - passing to kernel");
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(&ctx, "Redirecting packet to user space");
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match XSK_MAP.redirect(queue_id, 0) {
        Ok(ret) => Ok(ret),
        Err(_) => {
            error!(&ctx, "Failed to redirect packet");
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_dst_v4(ctx: &XdpContext) -> Result<IpAddr, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let ipv4hdr = unsafe { *ipv4hdr };
    Ok(IpAddr::V4(ipv4hdr.dst_addr()))
}

#[inline(always)]
fn get_dst_v6(ctx: &XdpContext) -> Result<IpAddr, ()> {
    let ipv6hdr: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let ipv6hdr = unsafe { *ipv6hdr };
    Ok(IpAddr::V6(ipv6hdr.dst_addr()))
}

#[inline(always)]
fn matches_filter(ip: IpAddr) -> bool {
    for i in 0..100 {
        match FILTER.get(i) {
            Some(filter) => {
                if filter.contains(ip) {
                    return true;
                }
            }
            None => break,
        }
    }
    false
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
