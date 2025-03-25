#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
use core::{
    cmp::min,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    u32,
};

#[derive(Clone, Copy)]
pub enum IpNetwork {
    V4(Ipv4Network),
    V6(Ipv6Network),
}

#[derive(Clone, Copy)]
pub struct Ipv4Network {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl IpNetwork {
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpNetwork::V4(network), IpAddr::V4(addr)) => network.contains(addr),
            (IpNetwork::V6(network), IpAddr::V6(addr)) => network.contains(addr),
            _ => false,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for IpNetwork {}

impl Ipv4Network {
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            addr,
            prefix_len: min(prefix_len, 32),
        }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - self.prefix_len);
        let addr = u32::from(addr);
        let self_addr = u32::from(self.addr);
        (addr & mask) == (self_addr & mask)
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for Ipv4Network {}

#[derive(Clone, Copy)]
pub struct Ipv6Network {
    addr: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Network {
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            addr,
            prefix_len: min(prefix_len, 128),
        }
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        // Get the segments of both the network address and the IP to check
        let segments = self.addr.segments();
        let other_segments = addr.segments();

        // Compare each 16-bit segment based on the prefix length
        for i in 0..8 {
            // Calculate how many bits to compare in this segment
            let bits_in_segment = match self.prefix_len {
                // If prefix is beyond this segment, all bits matter
                p if (i + 1) * 16 <= p as usize => 16,
                // If prefix starts in this segment, calculate partial segment bits
                p if i * 16 < p as usize => p as usize - i * 16,
                // If prefix is before this segment, no bits matter
                _ => 0,
            };

            // If no bits to compare, we're done checking
            if bits_in_segment == 0 {
                break;
            }

            // Create a mask for the bits we want to compare
            let mask = u16::MAX << (16 - bits_in_segment);

            // Compare the masked network segment with the masked IP segment
            if (segments[i] & mask) != (other_segments[i] & mask) {
                return false;
            }
        }
        // All segments match
        true
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for Ipv6Network {}
